import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

# Simulación de la base de datos de usuarios
# En un sistema real, esto estaría en una Base de Datos SQL o NoSQL, no creamos la base de datos ya que no se pide en el enunciado
db_users = {}

class UserSession:
    """Almacena la información del usuario que se loguea en el sistema."""
    def __init__(self, username, role, private_key):
        self.username = username
        self.role = role
        self.private_key = private_key

def register_user(username, password, role):
    """
    Registra un nuevo usuario (profesor o alumno).
    Genera un salt y hashea la contraseña con Scrypt.
    Genera un par de claves RSA (2048 bits).
    Cifra la clave privada usando la contraseña del usuario.
    Almacena salt, hash, rol, clave privada cifrada y clave pública.
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
        key_size=2048, # Longitud apropiada
    )
    public_key = private_key.public_key()
    
    # Cifrar y serializar la clave privada (protegida por contraseña)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    # Serializar la clave pública (no necesita protección)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Almacenar en la base de datos
    db_users[username] = {
        'salt': salt,
        'hash': password_hash,
        'role': role,
        'private_key_pem': private_key_pem,
        'public_key_pem': public_key_pem
    }
    print(f"INFO: Usuario '{username}' registrado con éxito.")

def login_user(username, password):
    """
    Autentica a un usuario y descifra su clave privada.
    Verifica el hash de la contraseña usando Scrypt.
    Si es correcto, usa la contraseña para descifrar la clave privada.
    Devuelve una sesión de usuario con la clave privada en memoria.
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
        # Esto podría pasar si la contraseña es correcta para Scrypt pero incorrecta para la librería de descifrado
        # Lo cubrimos aunque sea algo raro
        print(f"ERROR: Fallo al descifrar la clave privada de '{username}'.")
        raise ValueError("Autenticación fallida: no se pudo cargar la clave.")
        
    print(f"INFO: Login exitoso para '{username}'.")
    
    # Se crea la sesión de usuario
    return UserSession(username, user_data['role'], private_key)

def get_public_key_pem(username):
    """Obtiene la clave pública de un usuario (para cifrar datos para él)."""
    if username not in db_users:
        raise ValueError("Usuario no encontrado.")
    return db_users[username]['public_key_pem']
