import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def encrypt_grade_hybrid(grade_data_str, student_public_key_pem):
    """
    Cifra una calificación usando un esquema híbrido (AES + RSA).
    Genera una clave simétrica (AES-GCM) de un solo uso.
    Cifra la calificación (datos) con AES-GCM (Simétrico).
    Esto también genera una 'tag' de autenticación (MAC).
    Carga la clave pública RSA del estudiante.
    Cifra la clave simétrica (AES) con RSA-OAEP (Asimétrico).
    Devuelve todos los componentes necesarios para el descifrado.
    """
    
    # Generar clave simétrica (AES-256)
    sym_key = AESGCM.generate_key(bit_length=256) # Longitud apropiada
    aesgcm = AESGCM(sym_key)
    
    # Cifrado simétrico (AES-GCM)
    nonce = os.urandom(12) # Nonce único para GCM
    encrypted_grade = aesgcm.encrypt(
        nonce, 
        grade_data_str.encode('utf-8'), 
        None # 'Associated Data' (opcional)
    )
    # encrypted_grade contiene el ciphertext + la authentication tag
    
    # Cargar clave pública del estudiante
    student_public_key = serialization.load_pem_public_key(
        student_public_key_pem
    )
    
    # Cifrado asimétrico (RSA-OAEP) de la clave simétrica
    encrypted_sym_key = student_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"DEBUG: Cifrado: AES-GCM(256) + RSA-OAEP(2048)")
    return encrypted_grade, encrypted_sym_key, nonce

def decrypt_grade_hybrid(encrypted_grade, encrypted_sym_key, nonce, student_private_key):
    """
    Descifra una calificación.
    Usa la clave privada RSA del estudiante para descifrar la clave simétrica (AES).
    Usa la clave simétrica (AES-GCM) para descifrar la calificación.
    AES-GCM verifica automáticamente la etiqueta de autenticación (MAC).
       Si falla (InvalidTag), los datos fueron manipulados.
    """
    
    # Descifrado asimétrico (RSA-OAEP) para obtener la clave simétrica
    try:
        sym_key = student_private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"ERROR: Fallo al descifrar la clave simétrica con RSA: {e}")
        raise ValueError("Descifrado fallido (clave asimétrica).")

    # Descifrado simétrico (AES-GCM)
    aesgcm = AESGCM(sym_key)
    
    try:
        decrypted_data_bytes = aesgcm.decrypt(
            nonce,
            encrypted_grade,
            None # 'Associated Data'
        )
        # Verificación de MAC (implícita en AES-GCM.decrypt)
        print(f"DEBUG: Verificación de MAC (AES-GCM Tag): ÉXITO") 
        return decrypted_data_bytes.decode('utf-8')
        
    except InvalidTag:
        print(f"ERROR: ¡VERIFICACIÓN DE MAC FALLIDA! Los datos pueden estar corruptos o manipulados.")
        raise ValueError("Descifrado fallido: ¡la autenticación de la calificación es inválida!")
    except Exception as e:
        print(f"ERROR: Fallo en el descifrado AES-GCM: {e}")
        raise ValueError("Descifrado fallido (clave simétrica).")
