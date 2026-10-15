import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

#іменована константа для кількості ітерацій хешування пароля
PBKDF2_ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900


class User:
    def __init__(
        self, username: str, email: str, role: str, active: bool, password: str
    ):
        self.username = username
        self.email = email  # Викличе сеттер з @property
        self.role = role
        self.active = active
        self.__password_salt = os.urandom(16)
        self.__password_hash = self._hash_password(password)

    def _hash_password(self, password: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(16)
        self.__password_hash = self._hash_password(password)

    def check_password(self, password: str) -> bool:
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, new_hash)

    def deactivate(self) -> None:
        self.active = False

    @property
    def email(self) -> str:
        return self.__email

    @email.setter
    def email(self, value: str) -> None:
        # Локальна частина починається з латинської літери, має 3-64 символи (літери, цифри, крапки, дефіси, підкреслення),
        # далі '@' та доменне ім'я з принаймні однією крапкою.
        pattern = r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email: {value}")
        self.__email = value

    def __str__(self) -> str:
        return f"User(username='{self.username}', email='{self.email}', role='{self.role}', active={self.active})"


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: list[str] | set[str] | None = None,
    ):
        super().__init__(username, email, role="admin", active=True, password=password)
        self.permissions = set(permissions) if permissions is not None else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        return f"{base_str[:-1]}, permissions={list(self.permissions)})"


class Session:
    def __init__(self, ip: str, timeout_sec: int = SESSION_TIMEOUT_SEC):
        if timeout_sec <= 0:
            raise ValueError("Таймаут сесії має бути додатним числом.")
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time
        self.timeout_sec = timeout_sec

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self) -> bool:
        now = datetime.now(timezone.utc)
        elapsed = (now - self.last_activity).total_seconds()
        return elapsed <= self.timeout_sec


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self.records.append(record)

    def show_all(self) -> list[AuditRecord]:
        return self.records


class UserAccount:
    def __init__(self, user: User, session: Session | None = None):
        self.user = user
        self.session = session
        self.audit_log = AuditLog()

    def login(self, password: str, ip: str) -> bool:
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_failure_inactive")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_failure_wrong_password")
            return False

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        if self.session.is_active():
            self.session.touch()
            return True
        else:
            # Таймаут минув, завершуємо сеанс
            self.session = None
            return False

    def logout(self) -> None:
        if self.session is not None:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення має бути екземпляром класу User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Значення має бути екземпляром класу Session або None.")
            self.session = value
        else:
            raise KeyError(f"Зміна ключа '{key}' заборонена або не існує.")
