import os
import json
import base64
import pki_manager 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa # Corregido import
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

DB_FILE = "users_db.json"
db_users = {}

class UserSession:
    def __init__(self, username, role, private_key, certificate_pem):
        self.username = username
        self.role = role
        self.private_key = private_key
        self.certificate_pem = certificate_pem

def save_users_db():
    """Vuelca la base de datos de usuarios a disco en formato JSON (Base64)."""
    data_to_save = {}
    for username, data in db_users.items():
        data_to_save[username] = {
            'role': data['role'],
            'salt': base64.b64encode(data['salt']).decode('utf-8'),
            'hash': base64.b64encode(data['hash']).decode('utf-8'),
            'private_key_pem': base64.b64encode(data['private_key_pem']).decode('utf-8'),
            # Guardamos el certificado en lugar de la clave pública raw
            'certificate_pem': base64.b64encode(data['certificate_pem']).decode('utf-8')
        }
    
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        print(f"Error I/O guardando usuarios: {e}")

def load_users_db():
    """Carga usuarios desde JSON."""
    global db_users
    if not os.path.exists(DB_FILE):
        return

    try:
        with open(DB_FILE, 'r') as f:
            data_loaded = json.load(f)
            
        for username, data in data_loaded.items():
            db_users[username] = {
                'role': data['role'],
                'salt': base64.b64decode(data['salt']),
                'hash': base64.b64decode(data['hash']),
                'private_key_pem': base64.b64decode(data['private_key_pem']),
                'certificate_pem': base64.b64decode(data['certificate_pem'])
            }
    except Exception as e:
        print(f"Aviso: No se pudo cargar DB usuarios (puede estar vacía o corrupta): {e}")

# Cargar al inicio
load_users_db()

def register_user(username, password, role):
    """
    Registra usuario, genera par de claves y solicita un CERTIFICADO a la PKI.
    """
    if username in db_users:
        raise ValueError("El usuario ya existe.")
    
    # 1. Derivación de clave para proteger la clave privada (Scrypt)
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    password_hash = kdf.derive(password.encode())
    
    # 2. Generar par de claves RSA
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 3. Solicitar emisión de certificado a la CA (PKI)
    certificate_pem = pki_manager.issue_user_certificate(public_key, username, role)
    
    # 4. Cifrar clave privada para almacenamiento seguro
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    db_users[username] = {
        'salt': salt,
        'hash': password_hash,
        'role': role,
        'private_key_pem': private_key_pem,
        'certificate_pem': certificate_pem
    }
    
    save_users_db()
    print(f"Usuario '{username}' registrado y certificado emitido.")

def login_user(username, password):
    if username not in db_users:
        raise ValueError("Usuario no encontrado.")
    
    user_data = db_users[username]
    
    # Verificar contraseña
    kdf = Scrypt(salt=user_data['salt'], length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), user_data['hash'])
    except InvalidKey:
        raise ValueError("Credenciales inválidas.")
    
    # Descifrar clave privada
    try:
        private_key = serialization.load_pem_private_key(
            user_data['private_key_pem'],
            password=password.encode()
        )
    except ValueError:
        raise ValueError("Error interno descifrando clave privada.")
        
    return UserSession(username, user_data['role'], private_key, user_data['certificate_pem'])

def get_user_certificate(username):
    if username not in db_users:
        raise ValueError("Usuario no existe.")
    return db_users[username]['certificate_pem']
