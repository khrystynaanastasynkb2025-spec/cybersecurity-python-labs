import sys

from labs.lab02.task1 import Admin, User, UserAccount


def run_demo():
    print("Демонстрація завдання 1")

    # створення звичайного користувача
    try:
        user = User(
            username="khristy",
            email="khristy.secure@corp.ua",
            role="analyst",
            active=True,
            password="StrongPassword123!",
        )
        print(f"[OK] Створено користувача: {user}")
    except ValueError as e:
        print(f"[ERROR] Помилка створення користувача: {e}")

    # перевірка валідації email (хибний email викличе ValueError)
    print("\nТестування валідації email")
    try:
        print("Спроба встановити невалідний email: 'bad-email'")
        user.email = "bad-email"
    except ValueError as e:
        print(f"[CAUGHT EXPECTED ERROR] {e}")

    # успішна зміна email
    user.email = "khristy.new@corp.ua"
    print(f"[OK] Email успішно змінено на: {user.email}")

    # створення адміністратора (наслідування від User)
    print("\nСтворення адміністратора та прав")
    admin = Admin(
        username="root_admin",
        email="admin@corp.ua",
        password="AdminPassword999!",
        permissions=["read_logs", "manage_users"],
    )
    print(f"[OK] Створено адміна: {admin}")

    admin.grant_permission("delete_records")
    print(f"[OK] Додано новий дозвіл. Поточні права admin: {list(admin.permissions)}")
    print(f"Чи має право 'delete_records': {admin.has_permission('delete_records')}")

    # робота з UserAccount (композиція, вхід, аудит, спеціальні методи)
    print("\nТестування UserAccount та аутентифікації")
    account = UserAccount(user=user)

    # невдалий вхід (неправильний пароль)
    login_failed = account.login(password="WrongPassword", ip="192.168.1.50")
    print(f"Спроба входу з неправильним паролем: успіх = {login_failed}")

    # успішний вхід
    login_success = account.login(password="StrongPassword123!", ip="192.168.1.50")
    print(f"Спроба входу з правильним паролем: успіх = {login_success}")
    print(f"Користувач автентифікований? {account.is_authenticated()}")

    # тестування спеціальних методів
    print("\nТестування __getitem__ та __setitem__")
    retrieved_user = account["user"]
    print(f"Отримано через account['user']: username = {retrieved_user.username}")

    # вихід із системи (Logout)
    print("\nЗавершення сеансу (Logout)")
    account.logout()
    print(f"Чи автентифікований після logout? {account.is_authenticated()}")

    # перегляд журналу подій AuditLog
    print("\nЖурнал подій AuditLog")
    for record in account.audit_log.show_all():
        print(
            f"Час (UTC): {record.timestamp} | Користувач: {record.username} | Дія: {record.action}"
        )


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    else:
        print("Використання: python -m labs.lab02.main demo")


if __name__ == "__main__":
    main()
