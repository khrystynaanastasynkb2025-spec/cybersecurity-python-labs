import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))


from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import main as run_task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("Лабораторна робота №1")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print("=" * 60 + "\n")

    print("Завдання 1")
    run_task1()
    print("\n" + "=" * 60 + "\n")

    print("Завдання 2")
    run_task2()
    print("\n" + "=" * 60 + "\n")

    print("Завдання 3")
    run_task3()
    print("\n" + "=" * 60)
    print("Усі завдання успішно виконані")


if __name__ == "__main__":
    main()
