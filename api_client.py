from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, Request
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone, date
from contextlib import asynccontextmanager
import httpx

from users_db import users_db
from credential import SECRET_KEY, ALGORITHM, DENTALINK_TOKEN

# Creating the async client
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.requests_client = httpx.AsyncClient()
    yield
    await app.requests_client.aclose()

# Creating the app
app = FastAPI(lifespan=lifespan)

# Authenticator
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Password hash
pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

# User model for authorization
class User(BaseModel):
    username: str
    disabled: bool | None = None
    hashed_password : str

# Token model for authorization
class Token(BaseModel):
    access_token: str
    token_type: str

# Root
@app.get("/")
def root():
    return {"message":"Hello World"}

# Token creator
def create_access_token(data: dict, expires_delta: timedelta | None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

# Validate user and return token if alright
async def validate_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate" : "Bearer"}
    )
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username: str = payload.get("user")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    userFull = User(**user)
    if userFull.disabled:
        raise credentials_exception
    return userFull

# Login
@app.post("/login")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user_dict = users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = User(**user_dict)
    if not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return Token(access_token=create_access_token({"user":user.username},timedelta(days=1)),token_type="bearer")

# Get all of the meetings with filters
@app.get("/citas")
async def get_citas(request: Request, user: Annotated[str, Depends(validate_user)], fecha_inicio : date | None = None, fecha_termino: date | None = None,
                    id_estado_cita: int | None = None, id_sucursal: int | None = None):
    requests_client = request.app.requests_client
    url = "https://api.dentalink.healthatom.com/api/v1/citas"
    headers = {"Authorization":"Token " + DENTALINK_TOKEN}
    params = []

    if fecha_inicio and fecha_termino:
        params.append(f'"fecha":[{{"gte":"{str(fecha_inicio)}"}},{{"lte":"{str(fecha_termino)}"}}]')
    elif fecha_inicio:
        params.append(f'"fecha":{{"gte":"{str(fecha_inicio)}"}}')
    elif fecha_termino:
        params.append(f'"fecha":{{"lte":"{str(fecha_termino)}"}}')
    
    if id_estado_cita:
        params.append(f'"id_estado":{{"eq":"{str(id_estado_cita)}"}}')

    if id_sucursal:
        url = "https://api.dentalink.healthatom.com/api/v1/sucursales/" + str(id_sucursal) + "/citas"

    if params:
        url = url + "?q={" + ','.join(params) + "}"

    response = await requests_client.get(url = url,headers = headers)
    return response.json()

# change state of meeting
@app.put("/cambiar_estado/{cita_id}")
async def update_estado(cita_id : int, request: Request, user: Annotated[str, Depends(validate_user)], nuevo_id_estado : int):
    requests_client = request.app.requests_client

    url = "https://api.dentalink.healthatom.com/api/v1/citas/" + str(cita_id)
    headers = {"Authorization":"Token " + DENTALINK_TOKEN}
    data = {"id_estado":nuevo_id_estado}

    response = await requests_client.put(url=url,headers=headers,data=data)

    return response.json()