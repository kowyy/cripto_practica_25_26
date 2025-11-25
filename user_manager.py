import os
import json
import base64
import pki_manager 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa 

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
        print(f"Aviso: No se pudo cargar DB usuarios: {e}")

# Cargar al inicio
load_users_db()

def register_user(username, password, role):
    """
    Registra usuario usando SHA-256 + Salt para la autenticación.
    """
    if username in db_users:
        raise ValueError("El usuario ya existe.")
    
    # 1. Hashing de contraseña (SHA-256 + Salt)
    # Generamos un salt aleatorio de 16 bytes
    salt = os.urandom(16)
    
    # Creamos el hash combinando salt y password
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)              # Añadimos el salt
    digest.update(password.encode()) # Añadimos la password
    password_hash = digest.finalize()
    
    # 2. Generar par de claves RSA (2048 bits)
    print(f"DEBUG [User Manager]: Generando claves RSA-2048 para {username}.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # 3. Solicitar emisión de certificado a la PKI
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
    print(f"Usuario '{username}' registrado (Auth: SHA-256).")

def login_user(username, password):
    if username not in db_users:
        raise ValueError("Usuario no encontrado.")
    
    user_data = db_users[username]
    
    # 1. Verificar contraseña usando SHA-256 + Salt almacenado
    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    # Recomputamos el hash con el salt guardado y la password introducida
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)
    digest.update(password.encode())
    computed_hash = digest.finalize()
    
    # Comprobación de bytes
    if computed_hash != stored_hash:
        raise ValueError("Credenciales inválidas (Password incorrecta).")
    
    # 2. Descifrar clave privada
    try:
        private_key = serialization.load_pem_private_key(
            user_data['private_key_pem'],
            password=password.encode()
        )
    except ValueError:
        raise ValueError("Error interno: La contraseña es válida para login pero no descifra la clave privada.")
        
    return UserSession(username, user_data['role'], private_key, user_data['certificate_pem'])

def get_user_certificate(username):
    if username not in db_users:
        raise ValueError("Usuario no existe.")
    return db_users[username]['certificate_pem']
