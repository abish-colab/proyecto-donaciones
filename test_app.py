import pytest
from fastapi.testclient import TestClient
from app import app, usuarios_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def limpiar_db():
    usuarios_db.clear()

def test_registro_exitoso():
    response = client.post("/registro", json={
        "nombre": "Banco de Alimentos Norte",
        "email": "contacto@banco.org",
        "password": "PasswordSegura123",
        "rol": "donante"
    })
    assert response.status_code == 201
    assert response.json()["rol"] == "donante"

def test_registro_correo_duplicado():
    client.post("/registro", json={
        "nombre": "Restaurante Uno",
        "email": "test@restaurante.com",
        "password": "Pass123",
        "rol": "donante"
    })
    response = client.post("/registro", json={
        "nombre": "Restaurante Dos",
        "email": "test@restaurante.com",
        "password": "Pass456",
        "rol": "donante"
    })
    assert response.status_code == 400
    assert response.json()["detail"] == "El correo ya se encuentra registrado"

def test_registro_rol_invalido():
    response = client.post("/registro", json={
        "nombre": "Falso Donante",
        "email": "hacker@test.com",
        "password": "123",
        "rol": "superhacker"
    })
    assert response.status_code == 400

def test_login_correcto_y_obtener_jwt():
    client.post("/registro", json={
        "nombre": "Supermercado Central",
        "email": "central@super.com",
        "password": "MiPassword123"
    })
    response = client.post("/login", json={
        "email": "central@super.com",
        "password": "MiPassword123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_password_incorrecta():
    client.post("/registro", json={
        "nombre": "Tienda A",
        "email": "a@tienda.com",
        "password": "CorrectPassword"
    })
    response = client.post("/login", json={
        "email": "a@tienda.com",
        "password": "WrongPassword"
    })
    assert response.status_code == 401

def test_acceso_ruta_protegida_con_token():
    client.post("/registro", json={
        "nombre": "Donante A",
        "email": "donante@test.com",
        "password": "Pass"
    })
    login_res = client.post("/login", json={
        "email": "donante@test.com",
        "password": "Pass"
    })
    token = login_res.json()["access_token"]
    
    res = client.get("/donaciones", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert len(res.json()["donaciones"]) > 0

def test_acceso_sin_token():
    res = client.get("/donaciones")
    assert res.status_code == 401

def test_acceso_token_invalido():
    res = client.get("/donaciones", headers={"Authorization": "Bearer tokenfalsotrucho123"})
    assert res.status_code == 401
