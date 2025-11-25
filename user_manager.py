import os
import json
import base64
import pki_manager # IMPORTANTE
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
    data_to_save = {}
    for username, data in db_users.items():
        data_to_save[username] = {
            'role': data['role'],
            'salt': base64.b64encode(data['salt']).decode('utf-8'),
            'hash': base64.b64encode(data['hash']).decode('utf-8'),
            'private_key_pem': base64.b64encode(data['private_key_pem']).decode('utf-8'),
            # Guardamos el certificado
            'certificate_pem': base64.b64encode(data['certificate_pem']).decode('utf-8')
        }
    with open(DB_FILE, 'w') as f:
        json.dump(data_to_save, f, indent=4)

def load_users_db():
    global db_users
    if not os.path.exists(DB_FILE): return
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
        print(f"ERROR: Fallo al cargar DB usuarios: {e}")

load_users_db()

def register_user(username, password, role):
    if username in db_users: raise ValueError("Usuario existe.")
    
    # 1. Generar claves
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    password_hash = kdf.derive(password.encode())
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 2. Emitir CERTIFICADO X.509 via PKI
    print(f"INFO: Solicitando certificado a la PKI para '{username}'...")
    certificate_pem = pki_manager.issue_user_certificate(public_key, username, role)
    
    # 3. Cifrar clave privada
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
    print(f"INFO: Usuario '{username}' registrado con Certificado X.509.")

def login_user(username, password):
    if username not in db_users: raise ValueError("Usuario no encontrado.")
    user_data = db_users[username]
    
    # Verificar password
    kdf = Scrypt(salt=user_data['salt'], length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), user_data['hash'])
    except InvalidKey:
        raise ValueError("Contraseña incorrecta.")
    
    # Descifrar privada
    private_key = serialization.load_pem_private_key(
        user_data['private_key_pem'], password=password.encode()
    )
    
    return UserSession(username, user_data['role'], private_key, user_data['certificate_pem'])

def get_user_certificate(username):
    if username not in db_users: raise ValueError("Usuario no encontrado.")
    return db_users[username]['certificate_pem']
