import os
import re
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography import x509

def get_timestamp():
    # Obtenemos la hora actual en UTC para usarla como sello de tiempo
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def validate_timestamp(timestamp_str, max_age_days=365):
    try:
        timestamp = datetime.datetime.fromisoformat(timestamp_str)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        if timestamp > now + datetime.timedelta(minutes=5):
            raise ValueError("Timestamp en el futuro")
        
        age = now - timestamp
        if age.days > max_age_days:
            raise ValueError(f"Timestamp demasiado antiguo: {age.days} días")
        
        return True
    except Exception as e:
        print(f"Error validando el timestamp: {e}")
        return False

def sign_data_with_timestamp(data_bytes, private_key):
    # Generamos una firma digital RSA-PSS incluyendo la fecha para evitar que se reutilice en el futuro
    timestamp = get_timestamp()
    
    data_to_sign = data_bytes + timestamp.encode('utf-8')
    
    print(f"DEBUG: Firmando datos con fecha {timestamp} usando RSA-PSS")
    
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature, timestamp

def verify_signature_with_timestamp(data_bytes, signature, timestamp, public_key):
    if not validate_timestamp(timestamp):
        print("DEBUG: La fecha de la firma no es válida")
        return False
    
    data_to_verify = data_bytes + timestamp.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"DEBUG: Firma válida confirmada con fecha {timestamp}")
        return True
    except InvalidSignature:
        print("DEBUG: La firma no es válida o los datos han cambiado")
        return False

def get_public_key_from_cert(cert_pem):
    # Extraemos la clave pública del certificado
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

def encrypt_grade_entry(grade_data_str, student_cert_pem, prof_cert_pem):
    # Obtenemos las claves públicas de ambos destinatarios
    student_pub_key = get_public_key_from_cert(student_cert_pem)
    prof_pub_key = get_public_key_from_cert(prof_cert_pem)
    
    # Generamos la clave simétrica (AES) efímera una sola vez
    sym_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    
    encrypted_grade = aesgcm.encrypt(nonce, grade_data_str.encode('utf-8'), None)
    
    # Encapsulamos la clave AES para el alumno
    enc_key_student = student_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )

    # Encapsulamos la misma clave AES para el profesor
    enc_key_prof = prof_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), 
            algorithm=hashes.SHA256(), 
            label=None
        )
    )
    
    print("DEBUG: Datos cifrados para Alumno y Profesor (Multi-Recipient).")
    return encrypted_grade, enc_key_student, enc_key_prof, nonce

def decrypt_grade_hybrid(encrypted_grade, encrypted_sym_key, nonce, private_key):
    try:
        # Recuperamos la clave simétrica usando la clave privada RSA
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"No se pudo descifrar la clave de sesión: {e}")

    # Usamos la clave AES recuperada para leer la nota
    aesgcm = AESGCM(sym_key)
    try:
        decrypted_data_bytes = aesgcm.decrypt(nonce, encrypted_grade, None)
        return decrypted_data_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Error de integridad: los datos parecen haber sido modificados")

def validate_password_strength(password):
    """
    Valida que la contraseña cumpla requisitos de seguridad
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if not re.search(r'[A-Z]', password):
        return False, "Debe contener al menos una mayúscula"
    
    if not re.search(r'[a-z]', password):
        return False, "Debe contener al menos una minúscula"
    
    if not re.search(r'[0-9]', password):
        return False, "Debe contener al menos un número"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Debe contener al menos un carácter especial"
    
    return True, "Contraseña válida"
