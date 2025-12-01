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
    temp_file = DB_GRADES_FILE + ".tmp"
    data_to_save = {}
    
    for username, grades_list in db_grades.items():
        serializable_list = []
        for (enc_grade, enc_key_student, enc_key_prof, nonce, signature, signer, timestamp) in grades_list:
            serializable_list.append({
                'enc_grade': base64.b64encode(enc_grade).decode('utf-8'),
                'enc_key_student': base64.b64encode(enc_key_student).decode('utf-8'),
                'enc_key_prof': base64.b64encode(enc_key_prof).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'signer': signer,
                'timestamp': timestamp 
            })
        data_to_save[username] = serializable_list

    try:
        with open(temp_file, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        os.replace(temp_file, DB_GRADES_FILE)
        print("DEBUG: Base de datos de notas guardada (Estructura Actualizada).")
    except IOError as e:
        print(f"Error al guardar notas: {e}")
        if os.path.exists(temp_file): os.remove(temp_file)

def load_grades_db():
    global db_grades
    if not os.path.exists(DB_GRADES_FILE):
        return
    
    try:
        with open(DB_GRADES_FILE, 'r') as f:
            data = json.load(f)
            
        for username, g_list in data.items():
            restored = []
            for item in g_list:
                try:
                    enc_key_prof_b64 = item.get('enc_key_prof')
                    enc_key_prof = base64.b64decode(enc_key_prof_b64) if enc_key_prof_b64 else None

                    restored.append((
                        base64.b64decode(item['enc_grade']),
                        base64.b64decode(item['enc_key_student']),
                        enc_key_prof,
                        base64.b64decode(item['nonce']),
                        base64.b64decode(item['signature']),
                        item['signer'],
                        item.get('timestamp', "")
                    ))
                except Exception as e:
                    print(f"Nota corrupta ignorada: {e}")
            db_grades[username] = restored
        print(f"INFO: Notas cargadas.")
    except Exception as e:
        print(f"Error al cargar notas: {e}")

load_grades_db()

def add_grade(prof_session, student_username, subject, grade):
    if prof_session.role != 'profesor':
        raise PermissionError("Solo profesores.")
    
    try:
        role = user_manager.get_user_role(student_username)
        if role != 'alumno':
            print(f"Error: {student_username} no es un alumno.")
            audit_log.log_event(prof_session.username, "ADD_GRADE", student_username, "FAIL_INVALID_ROLE")
            return
            
        student_cert_pem = user_manager.get_user_certificate(student_username)
        if not pki_manager.verify_certificate(student_cert_pem):
            print(f"Error: Certificado de {student_username} inválido.")
            return
            
    except ValueError:
        print(f"Error: Alumno {student_username} no encontrado.")
        return

    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    signature, timestamp = crypto_manager.sign_data_with_timestamp(
        grade_data_str.encode('utf-8'), 
        prof_session.private_key
    )
    
    enc_grade, enc_key_student, enc_key_prof, nonce = crypto_manager.encrypt_grade_entry(
        grade_data_str, 
        user_manager.get_user_certificate(student_username),
        prof_session.certificate_pem
    )
    
    if student_username not in db_grades:
        db_grades[student_username] = []
    
    db_grades[student_username].append(
        (enc_grade, enc_key_student, enc_key_prof, nonce, signature, prof_session.username, timestamp)
    )
    
    save_grades_db()
    grade_detail = f"{student_username} | {subject}: {grade}"
    audit_log.log_event(prof_session.username, "ADD_GRADE", grade_detail, "SUCCESS")
    print(f"Nota guardada y cifrada para ambos.")

def view_grades_professor(prof_session, student_username):
    if prof_session.role != 'profesor':
        raise PermissionError("Solo profesores.")
    
    if student_username not in db_grades:
        print(f"No hay notas para {student_username}.")
        return []

    print(f"\nNotas de {student_username} (Vista Profesor - Desencriptada)")
    
    visible_grades = []
    for i, entry in enumerate(db_grades[student_username]):
        (enc_grade, enc_key_student, enc_key_prof, nonce, signature, signer, timestamp) = entry
        
        if signer == prof_session.username:
            try:
                content = "Contenido no disponible (Formato antiguo)"
                
                if enc_key_prof:
                    content = crypto_manager.decrypt_grade_hybrid(
                        enc_grade, 
                        enc_key_prof,
                        nonce, 
                        prof_session.private_key
                    )
                
                print(f"[{i}] {content}")
                print(f"    Firma válida fecha: {timestamp}")
                visible_grades.append((i, signer, timestamp))
                
            except Exception as e:
                print(f"[{i}] Error al descifrar nota propia: {e}")

    return visible_grades

def modify_grade(prof_session, student_username, index, new_grade_str):
    # Modificamos una nota, lo que implica volver a firmar y cifrar
    if prof_session.role != 'profesor':
        raise PermissionError("Solo profesores.")
    
    # Validamos que existe la nota y es suya
    if student_username not in db_grades or index >= len(db_grades[student_username]):
        raise ValueError("Nota no encontrada.")

    existing_entry = db_grades[student_username][index]
    if existing_entry[5] != prof_session.username:
        raise PermissionError("No puedes modificar notas de otros.")

    old_grade_str = "Contenido previo no disponible"
    try:
        (old_enc_grade, _, old_enc_key_prof, old_nonce, _, _, _) = existing_entry
        if old_enc_key_prof:
            old_grade_str = crypto_manager.decrypt_grade_hybrid(
                old_enc_grade,
                old_enc_key_prof,
                old_nonce,
                prof_session.private_key
            )
    except Exception as e:
        print(f"Advertencia: No se pudo leer la nota anterior: {e}")

    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
    except ValueError:
        print("Error obteniendo certificado del alumno.")
        return

    print(f"Modificando nota {index}...")
    
    signature, timestamp = crypto_manager.sign_data_with_timestamp(
        new_grade_str.encode('utf-8'), 
        prof_session.private_key
    )
    
    enc_grade, enc_key_student, enc_key_prof, nonce = crypto_manager.encrypt_grade_entry(
        new_grade_str, 
        student_cert_pem,
        prof_session.certificate_pem 
    )

    db_grades[student_username][index] = (
        enc_grade, enc_key_student, enc_key_prof, nonce, signature, prof_session.username, timestamp
    )
    
    save_grades_db()
    
    change_detail = f"{student_username} | ANTES: [{old_grade_str}] → AHORA: [{new_grade_str}]"
    audit_log.log_event(prof_session.username, "MODIFY_GRADE", change_detail, "SUCCESS")
    
    print("Nota modificada correctamente.")

def delete_grade(prof_session, student_username, index):
    if prof_session.role != 'profesor': raise PermissionError("Solo profesores.")
    
    if student_username not in db_grades or index >= len(db_grades[student_username]):
        raise ValueError("Índice incorrecto.")

    entry = db_grades[student_username][index]
    if entry[5] != prof_session.username: 
        raise PermissionError("No es tu nota.")
    
    del db_grades[student_username][index]
    save_grades_db()
    audit_log.log_event(prof_session.username, "DELETE_GRADE", student_username, "SUCCESS")
    print("Nota borrada.")

def delete_all_grades_of_student(student_username):
    # Borra todo el historial de un alumno
    if student_username in db_grades:
        del db_grades[student_username]
        save_grades_db()

def view_my_grades(student_session):
    # El alumno ve sus notas descifradas y verifica la firma
    if student_session.role != 'alumno': raise PermissionError("Solo alumnos.")
    u_name = student_session.username
    if u_name not in db_grades: return
        
    print(f"\nBoletín de {u_name}")
    for i, entry in enumerate(db_grades[u_name]):
        (enc_grade, enc_key_student, enc_key_prof, nonce, signature, signer, timestamp) = entry
        try:
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade, enc_key_student, nonce, student_session.private_key
            )
            
            signer_cert = user_manager.get_user_certificate(signer)
            signer_pub = crypto_manager.get_public_key_from_cert(signer_cert)
            
            is_valid = crypto_manager.verify_signature_with_timestamp(
                grade_str.encode('utf-8'), signature, timestamp, signer_pub
            )
            status = "VÁLIDA" if is_valid else "INVÁLIDA"
            
            print(f"{i+1}. {grade_str}")
            print(f"   Firma de: {signer} | Fecha: {timestamp} | Estado: {status}")
            
        except Exception as e:
            print(f"Error leyendo nota {i+1}: {e}")
    
    audit_log.log_event(student_session.username, "VIEW_GRADES", "Self", "SUCCESS")
