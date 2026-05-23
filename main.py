import os
import json
import asyncpg
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List

# ---- настройки ----
SECRET_KEY = os.environ["SECRET_KEY"]
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 неделя

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ---- вспомогательные функции ----
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login: str = payload.get("sub")
        role: str = payload.get("role")
        if login is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"login": login, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---- создание таблиц ----
CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS users (
    login TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    middle_name TEXT,
    birth_date TEXT,
    gender TEXT
);

CREATE TABLE IF NOT EXISTS tests (
    id TEXT PRIMARY KEY,
    time_limit_minutes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS questions (
    id SERIAL PRIMARY KEY,
    test_id TEXT REFERENCES tests(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    options JSONB NOT NULL,
    correct_index INTEGER DEFAULT 0,
    multiple BOOLEAN DEFAULT FALSE,
    correct_indices JSONB DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS test_results (
    id SERIAL PRIMARY KEY,
    student_login TEXT,
    test_id TEXT REFERENCES tests(id) ON DELETE CASCADE,
    answers JSONB NOT NULL DEFAULT '[]',
    percent INTEGER DEFAULT 0,
    completion_time_millis BIGINT DEFAULT 0
);
"""

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: создаём пул и таблицы
    app.state.pool = await asyncpg.create_pool(os.environ["DATABASE_URL"])
    async with app.state.pool.acquire() as conn:
        await conn.execute(CREATE_TABLES)
    yield
    # Shutdown
    await app.state.pool.close()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- эндпоинты ----

@app.get("/")
async def root():
    return {"message": "Quiz API"}

# Регистрация
@app.post("/register")
async def register(body: dict):
    login = body["login"]
    password = get_password_hash(body["password"])
    role = body["role"]
    last_name = body.get("lastName", "")
    first_name = body.get("firstName", "")
    middle_name = body.get("middleName", "")
    birth_date = body.get("birthDate", "")
    gender = body.get("gender", "")

    async with app.state.pool.acquire() as conn:
        try:
            await conn.execute(
                "INSERT INTO users (login, password, role, last_name, first_name, middle_name, birth_date, gender) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                login, password, role, last_name, first_name, middle_name, birth_date, gender
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=400, detail="Login already exists")
    token = create_access_token({"sub": login, "role": role})
    return {"token": token, "role": role}

# Вход
@app.post("/login")
async def login(body: dict):
    login = body["login"]
    password = body["password"]
    async with app.state.pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE login = $1", login)
        if not user or not verify_password(password, user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": login, "role": user["role"]})
    return {"token": token, "role": user["role"]}

# Получить профиль
@app.get("/profile")
async def get_profile(current_user = Depends(get_current_user)):
    async with app.state.pool.acquire() as conn:
        user = await conn.fetchrow("SELECT * FROM users WHERE login = $1", current_user["login"])
        return dict(user) if user else {}

# Обновить профиль
@app.put("/profile")
async def update_profile(body: dict, current_user = Depends(get_current_user)):
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_name=$1, first_name=$2, middle_name=$3, birth_date=$4, gender=$5 WHERE login=$6",
            body["lastName"], body["firstName"], body.get("middleName", ""),
            body["birthDate"], body["gender"], current_user["login"]
        )
    return {"status": "ok"}

# Создать тест (teacher only)
@app.post("/tests")
async def create_test(body: dict, current_user = Depends(get_current_user)):
    if current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher can create tests")
    test_id = body["id"]
    time_limit = body.get("timeLimitMinutes", 0)
    questions = body["questions"]
    async with app.state.pool.acquire() as conn:
        await conn.execute("INSERT INTO tests (id, time_limit_minutes) VALUES ($1, $2)", test_id, time_limit)
        for q in questions:
            await conn.execute(
                "INSERT INTO questions (test_id, text, options, correct_index, multiple, correct_indices) "
                "VALUES ($1, $2, $3, $4, $5, $6)",
                test_id, q["text"], json.dumps(q["options"]), q.get("correctIndex", 0),
                q.get("multiple", False), json.dumps(q.get("correctIndices", []))
            )
    return {"id": test_id}

# Получить тесты преподавателя (или все тесты для проверки существования)
@app.get("/tests")
async def get_tests(current_user = Depends(get_current_user)):
    if current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher")
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, time_limit_minutes FROM tests")
        tests = []
        for row in rows:
            q_rows = await conn.fetch("SELECT * FROM questions WHERE test_id = $1", row["id"])
            questions = []
            for q in q_rows:
                questions.append({
                    "text": q["text"],
                    "options": json.loads(q["options"]),
                    "correctIndex": q["correct_index"],
                    "multiple": q["multiple"],
                    "correctIndices": json.loads(q["correct_indices"])
                })
            tests.append({
                "id": row["id"],
                "timeLimitMinutes": row["time_limit_minutes"],
                "questions": questions
            })
        return tests

# Получить один тест по ID (для студента)
@app.get("/tests/{test_id}")
async def get_test(test_id: str, current_user = Depends(get_current_user)):
    if current_user["role"] != "student":
        raise HTTPException(status_code=403, detail="Only student")
    async with app.state.pool.acquire() as conn:
        test_row = await conn.fetchrow("SELECT * FROM tests WHERE id = $1", test_id)
        if not test_row:
            raise HTTPException(status_code=404, detail="Test not found")
        q_rows = await conn.fetch("SELECT * FROM questions WHERE test_id = $1", test_id)
        questions = []
        for q in q_rows:
            questions.append({
                "text": q["text"],
                "options": json.loads(q["options"]),
                "correctIndex": q["correct_index"],
                "multiple": q["multiple"],
                "correctIndices": json.loads(q["correct_indices"])
            })
        return {"id": test_row["id"], "timeLimitMinutes": test_row["time_limit_minutes"], "questions": questions}

# Сохранить результат студента
@app.post("/tests/{test_id}/results")
async def save_result(test_id: str, body: dict, current_user = Depends(get_current_user)):
    if current_user["role"] != "student":
        raise HTTPException(status_code=403, detail="Only student")
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO test_results (student_login, test_id, answers, percent, completion_time_millis) "
            "VALUES ($1, $2, $3, $4, $5)",
            current_user["login"], test_id, json.dumps(body["answers"]),
            body["percent"], body.get("completionTimeMillis", 0)
        )
    return {"status": "ok"}

# Получить результаты по тесту (для teacher)
@app.get("/tests/{test_id}/results")
async def get_results(test_id: str, current_user = Depends(get_current_user)):
    if current_user["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Only teacher")
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM test_results WHERE test_id = $1", test_id)
        results = []
        for row in rows:
            results.append({
                "studentLogin": row["student_login"],
                "testId": test_id,
                "answers": json.loads(row["answers"]),
                "percent": row["percent"],
                "completionTimeMillis": row["completion_time_millis"]
            })
        return results

# История студента
@app.get("/my-results")
async def get_my_results(current_user = Depends(get_current_user)):
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM test_results WHERE student_login = $1 ORDER BY id DESC",
            current_user["login"]
        )
        results = []
        for row in rows:
            results.append({
                "testId": row["test_id"],
                "percent": row["percent"],
                "completionTimeMillis": row["completion_time_millis"]
            })
        return results