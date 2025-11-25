import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography import x509

def sign_data(data_bytes, private_key):
    """
    Genera una firma digital utilizando RSA-PSS.
    """
    print(f"DEBUG [Cripto]: Generando firma digital. Algoritmo: RSA-PSS (SHA-256). Longitud Clave: {private_key.key_size} bits.")
    
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
    """
    Verifica una firma digital RSA-PSS.
    Devuelve True si es válida, False en caso contrario.
    """
    print(f"DEBUG [Cripto]: Verificando firma digital. Algoritmo: RSA-PSS (SHA-256). Longitud Clave Pública: {public_key.key_size} bits.")
    
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
        print("DEBUG [Cripto]: Resultado verificación -> VÁLIDA.")
        return True
    except InvalidSignature:
        print("DEBUG [Cripto]: Resultado verificación -> INVÁLIDA.")
        return False

def get_public_key_from_cert(cert_pem):
    """Extrae el objeto clave pública de un certificado PEM."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key()

def encrypt_grade_hybrid_two_parties(grade_data_str, student_cert_pem, prof_cert_pem):
    """
    Cifra la calificación para DOS destinatarios: el alumno y el profesor.
    """
    student_pub_key = get_public_key_from_cert(student_cert_pem)
    prof_pub_key = get_public_key_from_cert(prof_cert_pem)
    
    # Clave simétrica efímera
    print("DEBUG [Cripto]: Generando clave simétrica AES-GCM (256 bits).")
    sym_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    
    # Cifrado de datos (Simétrico)
    encrypted_grade = aesgcm.encrypt(
        nonce, 
        grade_data_str.encode('utf-8'), 
        None
    )
    
    # Cifrado de la clave simétrica para el Alumno (Asimétrico)
    print(f"DEBUG [Cripto]: Cifrando clave de sesión para Alumno. Algoritmo: RSA-OAEP. Longitud: {student_pub_key.key_size} bits.")
    enc_key_student = student_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Cifrado de la clave simétrica para el Profesor (Asimétrico)
    print(f"DEBUG [Cripto]: Cifrando clave de sesión para Profesor. Algoritmo: RSA-OAEP. Longitud: {prof_pub_key.key_size} bits.")
    enc_key_prof = prof_pub_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_grade, enc_key_student, enc_key_prof, nonce

def decrypt_grade_hybrid(encrypted_grade, encrypted_sym_key, nonce, private_key):
    """
    Descifra la calificación usando la clave privada proporcionada.
    """
    # Descifrado de la clave simétrica
    try:
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        raise ValueError("Fallo al descifrar la clave de sesión (RSA).")

    aesgcm = AESGCM(sym_key)
    
    # Descifrado de los datos
    try:
        decrypted_data_bytes = aesgcm.decrypt(
            nonce,
            encrypted_grade,
            None
        )
        print("DEBUG [Cripto]: Descifrado AES-GCM (256 bits) correcto. Integridad verificada.")
        return decrypted_data_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Integridad comprometida: Tag de autenticación inválido.")
