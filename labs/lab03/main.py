from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Реєстр вразливостей вебзастосунку (Lab 03)",
    description="Веб API для обліку знахідок перевірки вебзастосунку. Одиниця вимірювання: score (оцінка від 0 до 10).",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["System"])
def ping():
    return {"status": "ok"}


@app.get("/student", tags=["System"])
def get_student():
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
