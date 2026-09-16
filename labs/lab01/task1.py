import os
import random
import sys

# шлях для імпорту shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]
CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
}


def evaluate_password(password: str, all_passwords: list) -> str:
    min_len = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_special = any(not c.isalnum() for c in password)

    all_checks = [has_digit, has_upper, has_lower, has_special]

    if sum(all_checks) == 1:
        return "Слабкий"

    is_fully_secure = has_digit and has_upper and has_lower and has_special

    is_unique = all_passwords.count(password) == 1
    if is_fully_secure and len(password) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    if is_fully_secure and len(password) < min_len + 4:
        return "Сильний"

    return "Середній"


def run_task1():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    work_passwords = PASSWORDS.copy()

    random_indices = random.choices(range(len(work_passwords)), k=3)
    for idx in random_indices:
        work_passwords.append(work_passwords[idx])

    print(f"{'Пароль':<20} | {'Статус':<15}")
    print("-" * 38)
    for pwd in work_passwords:
        status = evaluate_password(pwd, work_passwords)
        print(f"{pwd:<20} | {status:<15}")


if __name__ == "__main__":
    run_task1()
