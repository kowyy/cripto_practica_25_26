import os
import json
import base64
import pki_manager
import audit_log
import crypto_manager
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa 

DB_FILE = "users_db.json"
db_users = {}

class UserSession:
    # Objeto simple para guardar los datos de la sesión actual
    def __init__(self, username, role, private_key, certificate_pem):
        self.username = username
        self.role = role
        self.private_key = private_key
        self.certificate_pem = certificate_pem

def save_users_db():
    # Guardamos los usuarios en disco de forma segura para evitar corrupción
    temp_file = DB_FILE + ".tmp"
    
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
        with open(temp_file, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        
        os.replace(temp_file, DB_FILE)
        print("DEBUG: Usuarios guardados.")
        
    except Exception as e:
        print(f"Error al guardar usuarios: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def load_users_db():
    # Cargamos los usuarios al iniciar el programa
    global db_users
    
    if not os.path.exists(DB_FILE):
        print("INFO: Base de datos de usuarios nueva.")
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
        
        print(f"INFO: {len(db_users)} usuarios cargados.")
        
    except Exception as e:
        print(f"Error cargando usuarios: {e}")

load_users_db()

def register_user(username, password, role):
    # Registramos un usuario nuevo
    if role not in ['profesor', 'alumno']:
        raise ValueError("Rol no válido (use profesor o alumno).")
    
    if username in db_users:
        raise ValueError("El usuario ya existe.")
    
    if not username:
        raise ValueError("El nombre no puede estar vacío.")
    
    print(f"INFO: Registrando a {username}...")
    
    # Creamos el hash de la contraseña con salt
    salt = os.urandom(16)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)              
    digest.update(password.encode()) 
    password_hash = digest.finalize()
    
    # Generamos sus claves criptográficas
    print("DEBUG: Generando claves RSA...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Pedimos el certificado a la autoridad
    print("DEBUG: Solicitando certificado...")
    certificate_pem = pki_manager.issue_user_certificate(public_key, username, role)
    
    # Ciframos la clave privada para guardarla
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    is_valid, message = crypto_manager.validate_password_strength(password)
    if not is_valid:
        audit_log.log_event("Anon", "REGISTER", username, "FAIL_WEAK_PASSWORD")
        raise ValueError(f"Contraseña débil: {message}")
    
    db_users[username] = {
        'salt': salt, 
        'hash': password_hash, 
        'role': role,
        'private_key_pem': private_key_pem, 
        'certificate_pem': certificate_pem
    }
    
    save_users_db()
    audit_log.log_event("System", "REGISTER_USER", username, "SUCCESS")
    
    print(f"Usuario registrado.")

def login_user(username, password):
    # Proceso de login
    if username not in db_users:
        audit_log.log_event("Anon", "LOGIN", username, "FAIL_NOT_FOUND")
        raise ValueError("Usuario no encontrado.")
    
    user_data = db_users[username]
    
    # Comprobamos que el certificado siga siendo válido
    if not pki_manager.verify_certificate(user_data['certificate_pem']):
        audit_log.log_event(username, "LOGIN", "System", "FAIL_CERT_REVOKED")
        raise ValueError("Acceso denegado: Certificado revocado o caducado.")

    # Verificamos la contraseña
    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)
    digest.update(password.encode())
    
    if digest.finalize() != stored_hash:
        audit_log.log_event(username, "LOGIN", "System", "FAIL_BAD_PASS")
        raise ValueError("Contraseña incorrecta.")
    
    # Intentamos desbloquear la clave privada
    try:
        private_key = serialization.load_pem_private_key(
            user_data['private_key_pem'], 
            password=password.encode()
        )
    except ValueError:
        raise ValueError("Error interno con la clave privada.")
    
    audit_log.log_event(username, "LOGIN", "System", "SUCCESS")
    print(f"Bienvenido {username}")
    
    return UserSession(username, user_data['role'], private_key, user_data['certificate_pem'])

def delete_user(username):
    # Borrado de usuario y revocación de credenciales
    if username not in db_users:
        raise ValueError("Usuario no existe.")
    
    cert_pem = db_users[username]['certificate_pem']
    pki_manager.revoke_certificate(cert_pem)
    
    del db_users[username]
    save_users_db()
    
    audit_log.log_event("Admin", "DELETE_USER", username, "SUCCESS_REVOKED")
    print(f"Usuario {username} eliminado.")

def get_user_certificate(username):
    # Helper para obtener certificado
    if username not in db_users:
        raise ValueError("Usuario no existe.")
    return db_users[username]['certificate_pem']

def get_user_role(username):
    # Helper para obtener el rol
    if username not in db_users:
        raise ValueError("Usuario no existe.")
    return db_users[username]['role']

def list_all_users():
    # Listado simple de usuarios
    if not db_users:
        print("No hay usuarios.")
        return
    
    print("\nLista de usuarios:")
    for username, data in db_users.items():
        print(f"- {username} ({data['role']})")
