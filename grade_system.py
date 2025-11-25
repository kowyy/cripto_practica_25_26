import os
import json
import base64
import user_manager
import crypto_manager
import pki_manager

DB_GRADES_FILE = "grades_db.json"
# Estructura: { 'alumno': [ (enc_grade, enc_key_stud, enc_key_prof, nonce, signature, signer_id), ... ] }
db_grades = {} 

def save_grades_db():
    """Guarda las calificaciones serializando bytes a Base64."""
    data_to_save = {}
    for username, grades_list in db_grades.items():
        serializable_list = []
        for (enc_grade, enc_key_s, enc_key_p, nonce, signature, signer) in grades_list:
            serializable_list.append({
                'enc_grade': base64.b64encode(enc_grade).decode('utf-8'),
                'enc_key_s': base64.b64encode(enc_key_s).decode('utf-8'), 
                'enc_key_p': base64.b64encode(enc_key_p).decode('utf-8'), 
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'signer': signer
            })
        data_to_save[username] = serializable_list

    try:
        with open(DB_GRADES_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        print(f"Error guardando notas: {e}")

def load_grades_db():
    """Carga calificaciones deserializando Base64."""
    global db_grades
    if not os.path.exists(DB_GRADES_FILE):
        return

    try:
        with open(DB_GRADES_FILE, 'r') as f:
            data_loaded = json.load(f)
            
        for username, grades_list_raw in data_loaded.items():
            restored_list = []
            for item in grades_list_raw:
                if 'enc_key_p' in item:
                    restored_list.append((
                        base64.b64decode(item['enc_grade']),
                        base64.b64decode(item['enc_key_s']),
                        base64.b64decode(item['enc_key_p']),
                        base64.b64decode(item['nonce']),
                        base64.b64decode(item['signature']),
                        item['signer']
                    ))
            db_grades[username] = restored_list
    except Exception:
        print("Aviso: DB de notas incompatible o corrupta. Se iniciará vacía.")

load_grades_db()

def add_grade(professor_session, student_username, subject, grade):
    """
    Añade una nota cifrada para el alumno Y para el profesor.
    Firma digitalmente la nota para asegurar autenticidad.
    """
    if professor_session.role != 'profesor':
        raise PermissionError("Solo profesores pueden añadir notas.")
        
    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
        if not pki_manager.verify_certificate(student_cert_pem):
            print(f"ERROR: Certificado del alumno inválido.")
            return
    except ValueError:
        print(f"ERROR: Alumno '{student_username}' no encontrado.")
        return

    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    # 1. Firmar (Integridad y No Repudio)
    signature = crypto_manager.sign_data(
        grade_data_str.encode('utf-8'), 
        professor_session.private_key
    )
    
    # 2. Cifrar (Confidencialidad Dual)
    enc_grade, enc_key_s, enc_key_p, nonce = \
        crypto_manager.encrypt_grade_hybrid_two_parties(
            grade_data_str, 
            student_cert_pem, 
            professor_session.certificate_pem
        )
        
    if student_username not in db_grades:
        db_grades[student_username] = []
        
    db_grades[student_username].append(
        (enc_grade, enc_key_s, enc_key_p, nonce, signature, professor_session.username)
    )
    
    save_grades_db()
    print(f"Nota guardada firmada y cifrada para '{student_username}'.")

def view_grades_professor(professor_session, student_username):
    """
    Permite al profesor ver las notas que ÉL ha puesto a un alumno.
    """
    if professor_session.role != 'profesor':
        raise PermissionError("Acceso denegado.")

    if student_username not in db_grades:
        print(f"No hay registros para {student_username}.")
        return []

    print(f"\n--- Notas de {student_username} (Vista Profesor) ---")
    visible_grades = []
    
    for i, entry in enumerate(db_grades[student_username]):
        (enc_grade, _, enc_key_p, nonce, _, signer) = entry
        
        if signer == professor_session.username:
            try:
                grade_str = crypto_manager.decrypt_grade_hybrid(
                    enc_grade, enc_key_p, nonce, professor_session.private_key
                )
                print(f"[{i}] {grade_str}")
                visible_grades.append((i, grade_str))
            except Exception as e:
                print(f"[{i}] Error descifrando: {e}")
    
    return visible_grades

def modify_grade(professor_session, student_username, index, new_grade_str):
    """
    Modifica una nota existente. Re-firma y re-cifra.
    """
    if professor_session.role != 'profesor':
        raise PermissionError("No autorizado.")
        
    if student_username not in db_grades or index >= len(db_grades[student_username]):
        raise ValueError("Nota no encontrada.")

    existing_entry = db_grades[student_username][index]
    if existing_entry[5] != professor_session.username: 
        raise PermissionError("No puedes modificar una nota que no creaste.")

    try:
        student_cert_pem = user_manager.get_user_certificate(student_username)
    except ValueError:
        print("Error recuperando credenciales del alumno.")
        return

    print(f"Modificando nota {index} para {student_username}...")
    
    # 1. Nueva Firma
    signature = crypto_manager.sign_data(
        new_grade_str.encode('utf-8'), 
        professor_session.private_key
    )
    
    # 2. Nuevo Cifrado Dual
    enc_grade, enc_key_s, enc_key_p, nonce = \
        crypto_manager.encrypt_grade_hybrid_two_parties(
            new_grade_str, 
            student_cert_pem, 
            professor_session.certificate_pem
        )

    db_grades[student_username][index] = (
        enc_grade, enc_key_s, enc_key_p, nonce, signature, professor_session.username
    )
    
    save_grades_db()
    print("Nota modificada y refirmada exitosamente.")

def view_my_grades(student_session):
    """
    Vista del alumno: Descifra y VERIFICA la firma digital.
    """
    if student_session.role != 'alumno':
        raise PermissionError("Solo alumnos.")
        
    student_username = student_session.username
    if student_username not in db_grades:
        print("No tienes notas.")
        return
        
    print(f"--- Boletín de {student_username} ---")
    for i, entry in enumerate(db_grades[student_username]):
        (enc_grade, enc_key_s, _, nonce, signature, signer) = entry
        try:
            # 1. Descifrar (Alumno)
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade, enc_key_s, nonce, student_session.private_key
            )
            
            # 2. Validar Firma
            # Recuperamos clave pública del firmante desde su certificado
            signer_cert = user_manager.get_user_certificate(signer)
            signer_pub = crypto_manager.get_public_key_from_cert(signer_cert)
            
            is_valid = crypto_manager.verify_signature(
                grade_str.encode('utf-8'), signature, signer_pub
            )
            validity = "VALIDADA" if is_valid else "INVALIDA"
            
            print(f"{i+1}. {grade_str}")
            print(f"   [Firma: {signer} ({validity})]")
            
        except Exception as e:
            print(f"{i+1}. Error de lectura: {e}")
