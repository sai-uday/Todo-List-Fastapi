from fastapi import FastAPI, HTTPException, Depends, Cookie, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import jwt
from jwt.exceptions import PyJWTError as JWTError
from passlib.context import CryptContext
from pymongo import MongoClient
from datetime import datetime, timedelta
from typing import Annotated, Optional
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Union
import asyncio
from datetime import datetime, timedelta
from typing import Annotated
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv


# FastAPI app
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
    allow_origins=["*"] 
)


# JWT settings
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

load_dotenv(dotenv_path="mndb .env")
my_variable = os.getenv("MY_VARIABLE")
# MongoDB connection
uri = my_variable
client = AsyncIOMotorClient(uri)
db = client["first"]
users_collection = db["first"]

# Password hashing
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 PasswordBearer for JWT token handling
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# User model
class UserInDB(BaseModel):
    username: str
    hashed_password: str
    data: list | None = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class login(BaseModel):
    username: str
    password: str


class signup(BaseModel):
    username: str
    password: str


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    datadb: dict | None = None


class todoitem(BaseModel):
    title: str
    desc: str


class index(BaseModel):
    index: int
# Function to get user from MongoDB
async def get_user(username: str) -> Union[UserInDB, None]:
    user_data = await users_collection.find_one({"username": username})
    if user_data:
        return UserInDB(**user_data)
    return None


# Function to verify password
def verify_password(plain_password, hashed_password):
    return password_context.verify(plain_password, hashed_password)


# Function to create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Access "sub" directly from the payload
        username: str = payload["sub"]
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)  # type: ignore
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user






# Routes


@app.get("/", tags=["all users"])
async def all():
    cursor = users_collection.find()
    documents = await cursor.to_list(length=None)
    # Convert ObjectId to string for serialization
    serialized_documents = []
    for doc in documents:
        doc['_id'] = str(doc['_id'])
        serialized_documents.append(doc)
    return {"documents": serialized_documents}





@app.post("/signup")
async def signup(data: login):
    data = dict(data)
    if ((await users_collection.find_one({"username": data["username"]}))):
        return "already exist"
    hashed_password = password_context.hash(data["password"])
    new_user = {"username": data["username"],
                "hashed_password": hashed_password, "data": []}
    await users_collection.insert_one(new_user)
    return "User registered successfully"


# Signin (Login)
@app.post("/signin")
async def signin(usercred: login):
    usercred = dict(usercred)
    user = await get_user(usercred["username"])
    if not user or not verify_password(usercred["password"], user.hashed_password):
        return "incorrect credentials"
    # print(user)
    # print(user.hashed_password)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires)

    response = JSONResponse(
        content={"access_token": access_token}, status_code=200)
    response.set_cookie(key="Authorization",
                        value=f"Bearer {access_token}", httponly=True)

    return response

# Delete user account


@app.delete("/delete/")
async def delete_account(username: str):
    result = users_collection.delete_one({"username": username})
    if result.deleted_count == 1:
        return {"message": f"User {username} deleted successfully"}
    else:
        return {"message": f"User {username} not found"}

# Protected route


@app.post("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Access "sub" directly from the payload
        username: str = payload["sub"]
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials")
    return {"message": f"You have access to this protected route, {username}!"}

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}






@app.post("/profile")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"username": current_user.username, "userdata": current_user.data}]


@app.post("/additem")
async def additem(current_user: Annotated[User, Depends(get_current_active_user)], data: todoitem):
    data = dict(data)
    await users_collection.update_one(
        {"username": current_user.username},
        {
            "$push": {
                "data": {
                    "title": data["title"],
                    "desc": data["desc"]
                }
            }
        }
    )
    a = await users_collection.find_one({"username": current_user.username})
    a = dict(a)
    return [{"userdata": a["data"]}]


@app.post("/deleteone")
async def deleteone(current_user: Annotated[User, Depends(get_current_active_user)],index: index):
    index=dict(index)
    a=index["index"]
    await users_collection.update_one({"username": current_user.username},{'$unset': {f"data.{a}": 1}})
    await users_collection.update_one({"username": current_user.username},{'$pull': {'data': None}})
    a = await users_collection.find_one({"username": current_user.username})
    a = dict(a)
    return [{"userdata": a["data"]}]
@app.delete("/deleteall")
async def deleteall(current_user: Annotated[User, Depends(get_current_active_user)]):
   await users_collection.update_one({ "username": current_user.username },{ '$set': { 'data': [] } })
   a = await users_collection.find_one({"username": current_user.username})
   a = dict(a)
   return [{"userdata": a["data"]}]
@app.get("/favicon.ico")
async def get_favicon():
    return Response(status_code=204)

# Run the FastAPI app

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
