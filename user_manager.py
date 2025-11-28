import os
import json
import base64
import pki_manager
import audit_log
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
    data_to_save = {}
    for username, data in db_users.items():
        data_to_save[username] = {
            'role': data['role'],
            'salt': base64.b64encode(data['salt']).decode('utf-8'),
            'hash': base64.b64encode(data['hash']).decode('utf-8'),
            'private_key_pem': base64.b64encode(data['private_key_pem']).decode('utf-8'),
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
    except Exception: pass

load_users_db()

def register_user(username, password, role):
    # Validación estricta
    if role not in ['profesor', 'alumno']:
        audit_log.log_event("Anon", "REGISTER", username, "FAIL_INVALID_ROLE")
        raise ValueError(f"Rol '{role}' no válido.")
        
    if username in db_users:
        audit_log.log_event("Anon", "REGISTER", username, "FAIL_USER_EXISTS")
        raise ValueError("El usuario ya existe.")
    
    # Criptografía
    salt = os.urandom(16)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)              
    digest.update(password.encode()) 
    password_hash = digest.finalize()
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Certificado PKI
    certificate_pem = pki_manager.issue_user_certificate(public_key, username, role)
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    db_users[username] = {
        'salt': salt, 'hash': password_hash, 'role': role,
        'private_key_pem': private_key_pem, 'certificate_pem': certificate_pem
    }
    
    save_users_db()
    audit_log.log_event("System", "REGISTER_USER", username, "SUCCESS")
    print(f"Usuario '{username}' registrado.")

def login_user(username, password):
    if username not in db_users:
        audit_log.log_event("Anon", "LOGIN", username, "FAIL_NOT_FOUND")
        raise ValueError("Usuario no encontrado.")
    
    user_data = db_users[username]
    
    # Verificar validez del certificado (Revocación)
    if not pki_manager.verify_certificate(user_data['certificate_pem']):
        audit_log.log_event(username, "LOGIN", "System", "FAIL_CERT_REVOKED")
        raise ValueError("Acceso denegado: Su certificado ha sido REVOCADO o caducado.")

    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(salt)
    digest.update(password.encode())
    if digest.finalize() != stored_hash:
        audit_log.log_event(username, "LOGIN", "System", "FAIL_BAD_PASS")
        raise ValueError("Contraseña incorrecta.")
    
    try:
        private_key = serialization.load_pem_private_key(
            user_data['private_key_pem'], password=password.encode()
        )
    except ValueError:
        raise ValueError("Error clave privada.")
        
    audit_log.log_event(username, "LOGIN", "System", "SUCCESS")
    return UserSession(username, user_data['role'], private_key, user_data['certificate_pem'])

def delete_user(username):
    if username not in db_users: raise ValueError("Usuario no existe.")
    
    # 1. Revocar certificado en la PKI
    cert_pem = db_users[username]['certificate_pem']
    pki_manager.revoke_certificate(cert_pem)
    
    # 2. Borrar de DB
    del db_users[username]
    save_users_db()
    
    audit_log.log_event("Admin", "DELETE_USER", username, "SUCCESS_REVOKED")
    print(f"Usuario '{username}' eliminado y certificado revocado.")

def get_user_certificate(username):
    if username not in db_users: raise ValueError("Usuario no existe.")
    return db_users[username]['certificate_pem']
