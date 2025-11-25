import os
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

# Nombre del archivo para persistencia
DB_FILE = "users_db.json"
db_users = {}

class UserSession:
    """Almacena la información del usuario que se loguea en el sistema."""
    def __init__(self, username, role, private_key):
        self.username = username
        self.role = role
        self.private_key = private_key

def save_users_db():
    """Serializa db_users a JSON, codificando bytes en Base64."""
    data_to_save = {}
    for username, data in db_users.items():
        data_to_save[username] = {
            'role': data['role'],
            # Codificar bytes a string Base64 para JSON
            'salt': base64.b64encode(data['salt']).decode('utf-8'),
            'hash': base64.b64encode(data['hash']).decode('utf-8'),
            'private_key_pem': base64.b64encode(data['private_key_pem']).decode('utf-8'),
            'public_key_pem': base64.b64encode(data['public_key_pem']).decode('utf-8')
        }
    
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        print(f"ERROR CRÍTICO: No se pudo guardar la base de datos de usuarios: {e}")

def load_users_db():
    """Carga usuarios desde JSON, decodificando Base64 a bytes."""
    global db_users
    if not os.path.exists(DB_FILE):
        return

    try:
        with open(DB_FILE, 'r') as f:
            data_loaded = json.load(f)
            
        for username, data in data_loaded.items():
            db_users[username] = {
                'role': data['role'],
                # Decodificar string Base64 a bytes
                'salt': base64.b64decode(data['salt']),
                'hash': base64.b64decode(data['hash']),
                'private_key_pem': base64.b64decode(data['private_key_pem']),
                'public_key_pem': base64.b64decode(data['public_key_pem'])
            }
        print(f"INFO: Base de datos de usuarios cargada ({len(db_users)} usuarios).")
    except (IOError, json.JSONDecodeError) as e:
        print(f"ERROR: No se pudo cargar la base de datos de usuarios: {e}")

# Cargar datos al importar el módulo
load_users_db()

def register_user(username, password, role):
    """
    Registra un nuevo usuario y guarda los cambios en disco.
    """
    if username in db_users:
        raise ValueError("El nombre de usuario ya existe.")
    
    print(f"INFO: Registrando a '{username}' ({role})...")
    
    # Hashing de contraseña con Scrypt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    password_hash = kdf.derive(password.encode())
    
    # Generación de claves Asimétricas (RSA)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
    )
    public_key = private_key.public_key()
    
    # Cifrar y serializar la clave privada (protegida por contraseña)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    # Serializar la clave pública
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Almacenar en memoria
    db_users[username] = {
        'salt': salt,
        'hash': password_hash,
        'role': role,
        'private_key_pem': private_key_pem,
        'public_key_pem': public_key_pem
    }
    
    # Guardar en archivo
    save_users_db()
    
    print(f"INFO: Usuario '{username}' registrado y guardado con éxito.")

def login_user(username, password):
    """
    Autentica a un usuario usando los datos cargados en memoria.
    """
    if username not in db_users:
        raise ValueError("Usuario no encontrado.")
        
    user_data = db_users[username]
    
    # Verificar el hash de la contraseña
    kdf = Scrypt(salt=user_data['salt'], length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), user_data['hash'])
    except InvalidKey:
        print(f"ERROR: Contraseña incorrecta para '{username}'.")
        raise ValueError("Autenticación fallida: contraseña incorrecta.")
    
    # Descifrar la clave privada con la contraseña
    try:
        private_key = serialization.load_pem_private_key(
            user_data['private_key_pem'],
            password=password.encode()
        )
    except (TypeError, ValueError):
        print(f"ERROR: Fallo al descifrar la clave privada de '{username}'.")
        raise ValueError("Autenticación fallida: no se pudo cargar la clave.")
        
    print(f"INFO: Login exitoso para '{username}'.")
    return UserSession(username, user_data['role'], private_key)

def get_public_key_pem(username):
    if username not in db_users:
        raise ValueError("Usuario no encontrado.")
    return db_users[username]['public_key_pem']
