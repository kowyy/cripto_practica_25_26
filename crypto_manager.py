import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography import x509

def get_timestamp():
    """Genera una marca de tiempo confiable (Simulación TSA)."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sign_data_with_timestamp(data_bytes, private_key):
    """
    Genera una firma digital RSA-PSS que INCLUYE un sello de tiempo.
    Esto evita ataques de repudio temporal.
    Devuelve: (firma, timestamp_str)
    """
    timestamp = get_timestamp()
    # Concatenamos datos + timestamp para firmar el conjunto
    data_to_sign = data_bytes + timestamp.encode('utf-8')
    
    print(f"DEBUG [Cripto]: Firmando datos + Timestamp ({timestamp}). Algoritmo: RSA-PSS 2048.")
    
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
    """
    Verifica la firma sobre (datos + timestamp).
    """
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
        print(f"DEBUG [Cripto]: Firma VÁLIDA. Timestamp certificado: {timestamp}")
        return True
    except InvalidSignature:
        print("DEBUG [Cripto]: Firma INVÁLIDA o Timestamp manipulado.")
        return False

def get_public_key_from_cert(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

def encrypt_grade_hybrid_two_parties(grade_data_str, student_cert_pem, prof_cert_pem):
    student_pub_key = get_public_key_from_cert(student_cert_pem)
    prof_pub_key = get_public_key_from_cert(prof_cert_pem)
    
    sym_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    
    encrypted_grade = aesgcm.encrypt(nonce, grade_data_str.encode('utf-8'), None)
    
    enc_key_student = student_pub_key.encrypt(
        sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    enc_key_prof = prof_pub_key.encrypt(
        sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    return encrypted_grade, enc_key_student, enc_key_prof, nonce

def decrypt_grade_hybrid(encrypted_grade, encrypted_sym_key, nonce, private_key):
    try:
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception:
        raise ValueError("Fallo al descifrar la clave de sesión (RSA).")

    aesgcm = AESGCM(sym_key)
    try:
        decrypted_data_bytes = aesgcm.decrypt(nonce, encrypted_grade, None)
        return decrypted_data_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Integridad comprometida: Tag de autenticación inválido.")
