from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
import psycopg2 as pg
from fastapi import FastAPI, Response, status, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI()

database = pg.connect(host="localhost", database="postgres", user="postgres", password="p5ssw0rd", keepalives=1)
cursor = database.cursor()


class User(BaseModel):
    id: int
    name: Optional[str] = None
    usertype: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    study_floor: Optional[int] = None
    study_seat: Optional[int] = None
    neis: Optional[int] = None
    office: Optional[str] = None


class Letter(BaseModel):
    id: str
    name: Optional[str] = None
    from_id: Optional[int] = None
    to_id: Optional[int] = None
    letter: Optional[str] = None
    is_anon: Optional[bool] = None
    is_secret: Optional[bool] = None
    present: Optional[str] = None


"""
/api			POST		418 I’m a Teapot // 연결 확인

/api/auth		POST		{id, password} // 로그인

/api/auth		GET		// 토큰 갱신

/api/auth		DELETE	// 로그아웃

/api/user		POST		{id, name, usertype, phone, password, study_floor, study_seat, grade, class, no, office} // 회원가입

/api/user		PATCH		{id, name, usertype, phone, password, study_floor, study_seat, grade, class, no, office} // 정보수정

/api/user		DELETE 	{password} // 회원탈퇴

/api/tree		GET		[id, name, usertype, grade-class] // 유저 검색

/api/tree/{uid}		GET		// 트리에 있는 편지 가져오기. return: {letter: [ {id, body, present}, ], count: {letter, present} }

/api/tree/{uid}/letter	POST		{name, letter, isAnon, isSecret, present}

/api/bill		GET		// 선물 결제 내역 확인. return: {order: [ {id, present, price, to, from, date}, ], total, isPaid}
"""


async def create_jwt(user_id: int):
    to_encode = {"id": user_id, "exp": datetime.utcnow() + timedelta(minutes=30), "iat": datetime.utcnow()}
    return jwt.encode(to_encode, "secret", algorithm="HS256")


async def BearerToken(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload.get("id")


@app.get("/api", status_code=status.HTTP_418_IM_A_TEAPOT)
async def root():
    return {"message": "I'm a Teapot"}


@app.post('/api/user', status_code=status.HTTP_201_CREATED)
async def create_user(user: User, response: Response):
    password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (
            user.id, user.name, user.usertype, user.phone, password, user.study_floor, user.study_seat,
            user.neis, user.office))
        database.commit()
    except pg.IntegrityError:
        response.status_code = status.HTTP_409_CONFLICT
        return {"message": "User already exists"}
    except pg.DataError:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "Invalid data"}

    response.headers["Authorization"] = await create_jwt(user.id)
    return {"message": "User created"}


@app.patch('/api/user', status_code=status.HTTP_200_OK)
async def update_user(user: User, response: Response, user_id: int = Depends(BearerToken)):
    if user_id != user.id:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"message": "Forbidden"}

    try:
        cursor.execute("UPDATE users SET name=%s, usertype=%s, phone=%s, password=%s, study_floor=%s, study_seat=%s, "
                       "neis=%s, office=%s WHERE id=%s", (user.name, user.usertype, user.phone, user.password,
                                                          user.study_floor, user.study_seat, user.neis, user.office,
                                                          user.id))
        database.commit()
    except pg.DataError:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": "Invalid data"}

    return {"message": "User updated"}


@app.delete('/api/user', status_code=status.HTTP_200_OK)
async def delete_user(response: Response, user_id: int = Depends(BearerToken)):
    try:
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        database.commit()
    except pg.IntegrityError:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "User not found"}

    return {"message": "User deleted"}


@app.post('/api/auth', status_code=status.HTTP_200_OK)
async def login(user: User, response: Response):
    try:
        cursor.execute("SELECT password FROM users WHERE id=%s", (user.id,))
        password = cursor.fetchone()[0]
    except pg.IntegrityError:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "User not found"}

    if bcrypt.checkpw(user.password.encode('utf-8'), password.encode('utf-8')):
        response.headers["Authorization"] = await create_jwt(user.id)
        return {"message": "Login success"}
    else:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "Login failed"}


@app.delete('/api/auth', status_code=status.HTTP_200_OK)
async def logout(response: Response):
    response.headers["Authorization"] = ""
    return {"message": "Logout success"}


@app.get('/api/auth', status_code=status.HTTP_200_OK)
async def check_auth(response: Response, user_id: int = Depends(BearerToken)):
    try:
        cursor.execute("SELECT name FROM users WHERE id=%s", (user_id,))
        name = cursor.fetchone()[0]
    except pg.IntegrityError:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"message": "User not found"}

    return {"message": "Login success", "name": name}


@app.get('/api/tree', status_code=status.HTTP_200_OK)
async def get_tree(id: int, name: str, type: str, grade: int, response: Response, user_id: int = Depends(BearerToken)):
    return {'id': id, 'name': name, 'type': type, 'grade': grade}
