# Лабораторна робота №4: Інтеграція із зовнішніми Web API та автоматизоване тестування Python-коду

## Варіант 1
- **Напрям відбору для ручного огляду:** Мережевий вектор атаки
- **Поріг оцінки CVSS v3.1 (`threshold`):** `7.0`
- **Поле (`field`):** `attackVector`
- **Очікуване значення (`expected`):** `NETWORK`
- **Правило відбору (`review`):** `score >= 7.0` та `cvssData["attackVector"] == "NETWORK"`

## Встановлення залежностей
У корені репозиторію в активованому віртуальному середовищі:
```bash
pip install -r requirements.txt
```

Локальний режим (робота із синтетичним JSON-файлом без мережі)
```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```
Онлайн-режим (одиночний запит до NVD CVE API 2.0)
```bash
python -m labs.lab04.main --cve CVE-2021-44228
```
## Формат звіту
На успішному запуску утиліта виводить у stdout JSON-об'єкт з такими полями:

cve_id - запитаний ідентифікатор CVE;

variant -номер варіанта (1);

description -англійський опис вразливості або null;

vuln_status -статус запису в NVD або null;

cvss_version -версія CVSS ("3.1") або null;

score -базова оцінка CVSS v3.1 або null;

score_source -джерело вибраної оцінки або null;

vector -рядок вектора CVSS v3.1 або null;

rule -об'єкт із параметрами правила (threshold, field, expected);

observed -фактичне значення поля attackVector або null;

decision -підсумковий стан (not_found, rejected, insufficient_data, review або other).

## Перевірка тестами та лінтером
```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```
