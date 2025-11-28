import os
import json
import base64
import user_manager
import crypto_manager
import pki_manager
import audit_log

DB_GRADES_FILE = "grades_db.json"
db_grades = {} 

def save_grades_db():
    data_to_save = {}
    for username, grades_list in db_grades.items():
        serializable_list = []
        for (enc_grade, enc_key_s, enc_key_p, nonce, signature, signer, timestamp) in grades_list:
            serializable_list.append({
                'enc_grade': base64.b64encode(enc_grade).decode('utf-8'),
                'enc_key_s': base64.b64encode(enc_key_s).decode('utf-8'), 
                'enc_key_p': base64.b64encode(enc_key_p).decode('utf-8'), 
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'signer': signer,
                'timestamp': timestamp 
            })
        data_to_save[username] = serializable_list

    try:
        with open(DB_GRADES_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        print(f"Error guardando notas: {e}")

def load_grades_db():
    global db_grades
    if not os.path.exists(DB_GRADES_FILE): return
    try:
        with open(DB_GRADES_FILE, 'r') as f:
            data = json.load(f)
        for u, g_list in data.items():
            restored = []
            for item in g_list:
                ts = item.get('timestamp', "") 
                restored.append((
                    base64.b64decode(item['enc_grade']),
                    base64.b64decode(item['enc_key_s']),
                    base64.b64decode(item['enc_key_p']),
                    base64.b64decode(item['nonce']),
                    base64.b64decode(item['signature']),
                    item['signer'],
                    ts
                ))
            db_grades[u] = restored
    except Exception: pass

load_grades_db()

def add_grade(prof_session, student_username, subject, grade):
    if prof_session.role != 'profesor': raise PermissionError("No autorizado.")
    
    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
        if not pki_manager.verify_certificate(student_cert_pem):
            print("Certificado alumno inválido/revocado.")
            return
    except ValueError:
        print("Alumno no encontrado.")
        return

    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    # 1. Firma con timestamp
    signature, timestamp = crypto_manager.sign_data_with_timestamp(
        grade_data_str.encode('utf-8'), 
        prof_session.private_key
    )
    
    # 2. Cifrado
    enc_grade, enc_key_s, enc_key_p, nonce = \
        crypto_manager.encrypt_grade_hybrid_two_parties(
            grade_data_str, student_cert_pem, prof_session.certificate_pem
        )
        
    if student_username not in db_grades: db_grades[student_username] = []
    
    # Guardamos la tupla de 7 elementos
    db_grades[student_username].append(
        (enc_grade, enc_key_s, enc_key_p, nonce, signature, prof_session.username, timestamp)
    )
    
    save_grades_db()
    audit_log.log_event(prof_session.username, "ADD_GRADE", student_username, "SUCCESS")
    print(f"Nota guardada y sellada temporalmente ({timestamp}).")

def view_grades_professor(prof_session, student_username):
    if prof_session.role != 'profesor': raise PermissionError("No autorizado.")
    if student_username not in db_grades: return []

    visible_grades = []
    print(f"--- Notas de {student_username} (Vista Profesor) ---")
    for i, entry in enumerate(db_grades[student_username]):
        (enc_grade, _, enc_key_p, nonce, _, signer, _) = entry
        
        if signer == prof_session.username:
            try:
                grade_str = crypto_manager.decrypt_grade_hybrid(
                    enc_grade, enc_key_p, nonce, prof_session.private_key
                )
                print(f"[{i}] {grade_str}")
                visible_grades.append((i, grade_str))
            except Exception: pass
    return visible_grades

def modify_grade(prof_session, student_username, index, new_grade_str):
    """
    Modifica una nota existente.
    Re-firma (con nuevo timestamp) y re-cifra todo el bloque.
    """
    if prof_session.role != 'profesor':
        raise PermissionError("No autorizado.")
        
    if student_username not in db_grades or index >= len(db_grades[student_username]):
        raise ValueError("Nota no encontrada.")

    # Verificar que la nota pertenece a este profesor antes de tocarla
    existing_entry = db_grades[student_username][index]
    # El índice 5 es 'signer'
    if existing_entry[5] != prof_session.username: 
        audit_log.log_event(prof_session.username, "MODIFY_GRADE", student_username, "FAIL_AUTH")
        raise PermissionError("No puedes modificar una nota que no creaste.")

    # Obtener certificado del alumno para re-cifrar
    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
    except ValueError:
        print("Error recuperando credenciales del alumno.")
        return

    print(f"Modificando nota {index} para {student_username}...")
    
    signature, timestamp = crypto_manager.sign_data_with_timestamp(
        new_grade_str.encode('utf-8'), 
        prof_session.private_key
    )
    
    enc_grade, enc_key_s, enc_key_p, nonce = \
        crypto_manager.encrypt_grade_hybrid_two_parties(
            new_grade_str, 
            student_cert_pem, 
            prof_session.certificate_pem
        )

    db_grades[student_username][index] = (
        enc_grade, enc_key_s, enc_key_p, nonce, signature, prof_session.username, timestamp
    )
    
    save_grades_db()
    audit_log.log_event(prof_session.username, "MODIFY_GRADE", student_username, "SUCCESS")
    print(f"Nota modificada y resellada ({timestamp}).")

def delete_grade(prof_session, student_username, index):
    if prof_session.role != 'profesor': raise PermissionError("No autorizado.")
    
    if student_username not in db_grades or index >= len(db_grades[student_username]):
        raise ValueError("Índice inválido.")

    entry = db_grades[student_username][index]
    if entry[5] != prof_session.username: 
        audit_log.log_event(prof_session.username, "DELETE_GRADE", student_username, "FAIL_AUTH")
        raise PermissionError("No es tu nota.")
    
    del db_grades[student_username][index]
    save_grades_db()
    audit_log.log_event(prof_session.username, "DELETE_GRADE", student_username, "SUCCESS")
    print("Nota eliminada.")

def delete_all_grades_of_student(student_username):
    if student_username in db_grades:
        del db_grades[student_username]
        save_grades_db()

def view_my_grades(student_session):
    if student_session.role != 'alumno': raise PermissionError("No autorizado.")
    u_name = student_session.username
    if u_name not in db_grades: return
        
    print(f"--- Boletín de {u_name} ---")
    for i, entry in enumerate(db_grades[u_name]):
        (enc_grade, enc_key_s, _, nonce, signature, signer, timestamp) = entry
        try:
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade, enc_key_s, nonce, student_session.private_key
            )
            
            signer_cert = user_manager.get_user_certificate(signer)
            signer_pub = crypto_manager.get_public_key_from_cert(signer_cert)
            
            is_valid = crypto_manager.verify_signature_with_timestamp(
                grade_str.encode('utf-8'), signature, timestamp, signer_pub
            )
            validity = "VALIDADA" if is_valid else "INVALIDA"
            
            print(f"{i+1}. {grade_str}")
            print(f"   [Firma: {signer} | Fecha Sello: {timestamp} | Estado: {validity}]")
            
        except Exception as e:
            print(f"Error nota {i+1}: {e}")
    
    audit_log.log_event(student_session.username, "VIEW_GRADES", "Self", "SUCCESS")
