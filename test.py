from datetime import datetime, timedelta

import jwt
from fastapi import FastAPI, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()


async def create_jwt(user_id: int):
    to_encode = {"id": user_id, "exp": datetime.utcnow() + timedelta(minutes=30), "iat": datetime.utcnow()}
    return jwt.encode(to_encode, "secret", algorithm="HS256")


@app.get("/create")
async def create():
    return await create_jwt(22017)


@app.get("/decode")
async def decode(token: str):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

    return payload


@app.get("/auth")
async def auth(token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    return token


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
