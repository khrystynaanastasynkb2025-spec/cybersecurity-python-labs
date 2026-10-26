import json
import sqlite3
from contextlib import closing

from labs.lab03.database import BASE_DIR, get_connection, initialize_database

SEED_PATH = BASE_DIR / "data" / "seed.json"


def seed_database() -> None:
    initialize_database()
    if not SEED_PATH.exists():
        print("Seed file not found.")
        return

    data = json.loads(SEED_PATH.read_text(encoding="utf-8"))

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            print("База вже містить дані. Пропускаємо початкове заповнення.")
            return

        try:
            with connection:
                for cat in data.get("categories", []):
                    connection.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (cat["id"], cat["name"]),
                    )

                for rec in data.get("records", []):
                    connection.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            rec["code"],
                            rec["title"],
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        ),
                    )
            print("Початкові дані успішно завантажено в базу.")
        except sqlite3.Error as e:
            print(f"Помилка під час заповнення бази: {e}")
            raise


if __name__ == "__main__":
    seed_database()
