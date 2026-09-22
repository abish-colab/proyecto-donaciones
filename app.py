from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
from datetime import datetime, timedelta

app = FastAPI(title="Sistema de Donacion de Alimentos")

SECRET_KEY = "clave_secreta_super_segura_tecmilenio"
ALGORITHM = "HS256"

usuarios_db = {}

class RegistroUsuario(BaseModel):
    nombre: str
    email: EmailStr
    password: str
    rol: str = "donante"

class LoginUsuario(BaseModel):
    email: EmailStr
    password: str

def encriptar_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verificar_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def crear_token(data: dict) -> str:
    datos_a_firmar = data.copy()
    expiracion = datetime.utcnow() + timedelta(hours=24)
    datos_a_firmar.update({"exp": expiracion})
    return jwt.encode(datos_a_firmar, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/registro", status_code=201)
def registrar_donante(usuario: RegistroUsuario):
    if usuario.email in usuarios_db:
        raise HTTPException(status_code=400, detail="El correo ya se encuentra registrado")
    
    if usuario.rol not in ["donante", "admin"]:
        raise HTTPException(status_code=400, detail="Rol invalido")

    usuarios_db[usuario.email] = {
        "nombre": usuario.nombre,
        "email": usuario.email,
        "password": encriptar_password(usuario.password),
        "rol": usuario.rol
    }
    return {"mensaje": "Donante registrado exitosamente", "email": usuario.email, "rol": usuario.rol}

@app.post("/login")
def login(credenciales: LoginUsuario):
    usuario = usuarios_db.get(credenciales.email)
    if not usuario or not verificar_password(credenciales.password, usuario["password"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    token = crear_token({"sub": usuario["email"], "rol": usuario["rol"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/donaciones")
def ver_donaciones(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente o formato invalido")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token no valido")
    
    return {
        "mensaje": f"Acceso concedido para {payload.get('sub')}",
        "rol": payload.get("rol"),
        "donaciones": [
            {"id": 1, "alimento": "Manzanas", "kilos": 50, "caducidad": "2026-10-15"},
            {"id": 2, "alimento": "Arroz", "kilos": 100, "caducidad": "2026-12-01"}
        ]
    }
