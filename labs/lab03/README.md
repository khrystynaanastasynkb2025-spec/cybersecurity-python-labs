# Лабораторна робота №3: Реєстр вразливостей вебзастосунку

## Встановлення

```bash
.venv\Scripts\Activate.ps1
pip install fastapi uvicorn pydantic ruff
```

## Ініціалізація та заповнення бази даних
```bash
python -m labs.lab03.seed
```

## Запуск API сервера
```bash
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

## Документація
Після запуску відкрити у браузері: http://127.0.0.1:8000/docs
## Приклади основних запитів

### 1. Перевірка статусу (Ping)
```bash
curl -X 'GET' '[http://127.0.0.1:8000/ping](http://127.0.0.1:8000/ping)' -H 'accept: application/json'
curl -X 'GET' '[http://127.0.0.1:8000/records?limit=10&offset=0](http://127.0.0.1:8000/records?limit=10&offset=0)' -H 'accept: application/json'
curl -X 'POST' '[http://127.0.0.1:8000/records](http://127.0.0.1:8000/records)' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "code": "V01-NEW-01",
  "title": "Знахідка вебаудиту",
  "category_id": 1,
  "value": 8.5,
  "status": "new"
}'
