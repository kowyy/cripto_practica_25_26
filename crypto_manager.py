import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography import x509

def sign_data(data_bytes, private_key):
    """Genera una firma digital RSA-PSS para los datos."""
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data_bytes, signature, public_key):
    """Verifica una firma digital RSA-PSS."""
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Asegurar que encrypt_grade_hybrid acepte ahora un objeto public_key 
# o extraiga la public key del certificado PEM.

def get_public_key_from_cert(cert_pem):
    """Extrae la clave pública de un certificado PEM."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

def encrypt_grade_hybrid_with_cert(grade_data_str, student_cert_pem):
    """Wrapper para usar certificado en lugar de clave pública raw."""
    student_public_key = get_public_key_from_cert(student_cert_pem)
    
    sym_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    encrypted_grade = aesgcm.encrypt(nonce, grade_data_str.encode('utf-8'), None)
    
    encrypted_sym_key = student_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_grade, encrypted_sym_key, nonce
