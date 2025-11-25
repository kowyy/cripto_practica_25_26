import os
import json
import base64
import user_manager
import crypto_manager
import pki_manager

DB_GRADES_FILE = "grades_db.json"
db_grades = {} 

def save_grades_db():
    data_to_save = {}
    for username, grades_list in db_grades.items():
        serializable_list = []
        for (enc_grade, enc_key, nonce, signature, signer) in grades_list:
            serializable_list.append({
                'enc_grade': base64.b64encode(enc_grade).decode('utf-8'),
                'enc_key': base64.b64encode(enc_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'signer': signer
            })
        data_to_save[username] = serializable_list
    with open(DB_GRADES_FILE, 'w') as f:
        json.dump(data_to_save, f, indent=4)

def load_grades_db():
    global db_grades
    if not os.path.exists(DB_GRADES_FILE): return
    try:
        with open(DB_GRADES_FILE, 'r') as f:
            data = json.load(f)
        for u, g_list in data.items():
            restored = []
            for item in g_list:
                restored.append((
                    base64.b64decode(item['enc_grade']),
                    base64.b64decode(item['enc_key']),
                    base64.b64decode(item['nonce']),
                    base64.b64decode(item['signature']),
                    item['signer']
                ))
            db_grades[u] = restored
    except Exception: pass

load_grades_db()

def add_grade(prof_session, student_username, subject, grade):
    if prof_session.role != 'profesor': raise PermissionError("No autorizado.")
    
    # 1. Obtener Certificado del alumno (para cifrar)
    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
        # Validar el certificado del alumno antes de usarlo
        if not pki_manager.verify_certificate(student_cert_pem):
            print(f"ALERTA: El certificado del alumno '{student_username}' no es válido.")
            return
    except ValueError:
        print("Alumno no existe."); return

    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    # 2. El profesor firma los datos en claro con su clave privada
    # Esto garantiza que "Jose Maria" escribió esa nota.
    signature = crypto_manager.sign_data(
        grade_data_str.encode('utf-8'), 
        prof_session.private_key
    )
    
    # 3. CIFRADO HÍBRIDO: Usando la pública del alumno (extraída de su cert)
    enc_grade, enc_key, nonce = crypto_manager.encrypt_grade_hybrid_with_cert(
        grade_data_str, student_cert_pem
    )
    
    if student_username not in db_grades: db_grades[student_username] = []
    
    # Guardamos todo: Cifrado + Firma + Identidad del firmante
    db_grades[student_username].append(
        (enc_grade, enc_key, nonce, signature, prof_session.username)
    )
    save_grades_db()
    print(f"INFO: Calificación firmada por '{prof_session.username}' y cifrada para '{student_username}'.")

def view_my_grades(student_session):
    if student_session.role != 'alumno': raise PermissionError("No autorizado.")
    
    u_name = student_session.username
    if u_name not in db_grades: print("Sin notas."); return
    
    print("\n-> Verificando y Descifrando Calificaciones...")
    for i, (enc_grade, enc_key, nonce, signature, signer) in enumerate(db_grades[u_name]):
        try:
            # 1. Descifrar el contenido
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade, enc_key, nonce, student_session.private_key
            )
            
            # 2. Obtener certificado del profesor (signer)
            signer_cert_pem = user_manager.get_user_certificate(signer)
            
            # 3. Validar el certificado del profesor contra la PKI
            if not pki_manager.verify_certificate(signer_cert_pem):
                print(f"  [AVISO SEGURIDAD] Certificado del profesor '{signer}' INVÁLIDO/REVOCADO.")
            
            # 4. Obtener clave pública del profesor del certificado
            prof_pub_key = crypto_manager.get_public_key_from_cert(signer_cert_pem)
            
            # 5. VERIFICAR LA FIRMA
            is_valid = crypto_manager.verify_signature(
                grade_str.encode('utf-8'),
                signature,
                prof_pub_key
            )
            
            status = "Firma VÁLIDA (Auténtico)" if is_valid else "Firma INVÁLIDA (Falsificado)"
            print(f"  Nota {i+1}: {grade_str}")
            print(f"          -> Firmado por: {signer} | Estado: {status}")
            
        except Exception as e:
            print(f"  Error al procesar nota {i+1}: {e}")
