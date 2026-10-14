# Лабораторна робота №2. Консольні утиліти для задач кібербезпеки

**Варіант 1:** Аналізатор журналів веб-сервера (Nginx/Apache Access Log)

## Встановлення

```bash
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Структура файлів

```
labs/lab02/
├── __init__.py
├── main.py
├── task1.py       
├── task2.py
├── README.md
└── data/
   └── access.log
```

## Вхідні дані

Програма приймає файл `labs/lab02/data/access.log`: текстовий журнал
доступу веб-сервера (Nginx/Apache) у форматі Common Log Format. Один запис
розташований в одному рядку.

Приклад рядка:

```
192.0.2.11 - - [27/Sep/2026:08:00:00 +0300] "GET /static/app.js HTTP/1.1" 204 7682
```

З кожного рядка програма за допомогою регулярного виразу витягує поля:

| Поле | Приклад |
|---|---|
| IP-адреса клієнта | `192.0.2.11` |
| Дата й час (з часовим поясом) | `27/Sep/2026:08:00:00 +0300` |
| HTTP-метод | `GET` |
| URI запиту | `/static/app.js` |
| Версія протоколу | `HTTP/1.1` |
| Статус-код | `204` |
| Розмір відповіді (байти) | `7682` |


## Запуск

Демонстрація Завдання 1:

```bash
python -m labs.lab02.main demo
```

Аналіз (Завдання 2):

```bash
python -m labs.lab02.task2 --log-file labs/lab02/data/access.log --output labs/lab02/data/web_analysis_report.json --min-status 400 --top 5 --format json
```

## Параметри CLI

| Параметр | Опис | Типове значення                         |
|---|---|-----------------------------------------|
| `--log-file` | шлях до access.log | labs/lab02/data/access.log              |
| `--output` | шлях до звіту | labs/lab02/data/web_analysis_report.json |
| `--min-status` | мінімальний статус-код | 400                                     |
| `--top` | кількість IP у топі | 5                                       |
| `--format` | json або csv | json                                    |

## Поведінка при помилках

- Файл не знайдено: повідомлення в лог, код завершення 1.
- Некоректний рядок логу: пропускається з попередженням.
- Невірний аргумент: argparse виводить помилку та довідку.

## Перевірка коду

```bash
ruff check .
ruff format --check .
```

посилання на коміт: https://github.com/khrystynaanastasynkb2025-spec/cybersecurity-python-labs/commit/06d2dce8eb4bd35c20853546500879344ce53759