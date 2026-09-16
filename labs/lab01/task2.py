import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "admin001": {
        "role": "administrator",
        "clearance": 4,
        "department": "IT",
        "active": True,
    },
    "user123": {
        "role": "analyst",
        "clearance": 2,
        "department": "Security",
        "active": True,
    },
    "guest789": {
        "role": "guest",
        "clearance": 1,
        "department": "External",
        "active": True,
    },
    "manager456": {
        "role": "manager",
        "clearance": 3,
        "department": "Operations",
        "active": True,
    },
    "contractor99": {
        "role": "contractor",
        "clearance": 1,
        "department": "External",
        "active": False,
    },
}

RESOURCES = [
    ("database_backup", 4),
    ("user_logs", 2),
    ("public_docs", 1),
    ("financial_reports", 3),
    ("system_config", 4),
    ("training_materials", 1),
    ("security_policies", 3),
    ("audit_logs", 4),
    ("employee_data", 3),
    ("temp_files", 1),
]

SECURITY_LEVELS = ("Public", "Internal", "Confidential", "Secret")
BLOCKED_USERS = {"contractor99", "temp_user", "suspended_acc"}


def display_resources():
    print("Список ресурсів системи")
    for res_name, level_num in RESOURCES:
        text_level = SECURITY_LEVELS[level_num - 1]
        print(f"Ресурс: {res_name:<20} | Рівень безпеки: {text_level}")
    print("-" * 50)


def check_access(username: str, resource_tuple: tuple) -> str:
    _, req_clearance = resource_tuple

    if username not in USERS:
        return "DENY (User not found)"

    if username in BLOCKED_USERS:
        return "DENY (User is blocked)"

    user_info = USERS[username]

    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    user_clearance = user_info.get("clearance", 0)
    if user_clearance >= req_clearance:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def run_task2():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )

    display_resources()

    print("Результати перевірки доступу")
    for username in USERS:
        for res in RESOURCES:
            res_name = res[0]
            result = check_access(username, res)
            print(f"user=[{username}] resource=[{res_name}] -> {result}")


if __name__ == "__main__":
    run_task2()
