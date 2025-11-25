import os
import json
import base64
import user_manager
import crypto_manager

# Nombre del archivo para persistencia
DB_GRADES_FILE = "grades_db.json"
db_grades = {} # { 'username_alumno': [ (enc_grade, enc_key, nonce), ... ] }

def save_grades_db():
    """Guarda las calificaciones en JSON (Base64 para datos binarios)."""
    data_to_save = {}
    for username, grades_list in db_grades.items():
        serializable_list = []
        for (enc_grade, enc_key, nonce) in grades_list:
            serializable_list.append({
                'enc_grade': base64.b64encode(enc_grade).decode('utf-8'),
                'enc_key': base64.b64encode(enc_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8')
            })
        data_to_save[username] = serializable_list

    try:
        with open(DB_GRADES_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except IOError as e:
        print(f"ERROR CRÍTICO: No se pudo guardar la base de datos de notas: {e}")

def load_grades_db():
    """Carga calificaciones y decodifica Base64."""
    global db_grades
    if not os.path.exists(DB_GRADES_FILE):
        return

    try:
        with open(DB_GRADES_FILE, 'r') as f:
            data_loaded = json.load(f)
            
        for username, grades_list_raw in data_loaded.items():
            restored_list = []
            for item in grades_list_raw:
                restored_list.append((
                    base64.b64decode(item['enc_grade']),
                    base64.b64decode(item['enc_key']),
                    base64.b64decode(item['nonce'])
                ))
            db_grades[username] = restored_list
        print(f"INFO: Base de datos de calificaciones cargada.")
    except (IOError, json.JSONDecodeError) as e:
        print(f"ERROR: No se pudo cargar la base de datos de notas: {e}")

# Cargar al importar
load_grades_db()

def add_grade(professor_session, student_username, subject, grade):
    """
    Profesor añade una nueva calificación cifrada y la guarda en disco.
    """
    if professor_session.role != 'profesor':
        raise PermissionError("Acción no autorizada. Solo los profesores pueden añadir notas.")
        
    print(f"\nACCIÓN: Profesor '{professor_session.username}' añade nota para '{student_username}'...")
    
    try:
        student_public_key_pem = user_manager.get_public_key_pem(student_username)
    except ValueError:
        print(f"ERROR: El estudiante '{student_username}' no existe.")
        return

    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    encrypted_grade, encrypted_sym_key, nonce = \
        crypto_manager.encrypt_grade_hybrid(grade_data_str, student_public_key_pem)
        
    if student_username not in db_grades:
        db_grades[student_username] = []
        
    db_grades[student_username].append(
        (encrypted_grade, encrypted_sym_key, nonce)
    )
    
    # Guardar cambios
    save_grades_db()
    
    print(f"INFO: Calificación cifrada, almacenada y persistida para '{student_username}'.")

def view_my_grades(student_session):
    """
    El alumno ve todas sus calificaciones descifradas.
    """
    if student_session.role != 'alumno':
        raise PermissionError("Acción no autorizada. Solo los alumnos pueden ver sus notas.")
        
    print(f"\nAlumno '{student_session.username}' solicita ver sus notas...")
    
    student_username = student_session.username
    if student_username not in db_grades or not db_grades[student_username]:
        print("INFO: No tienes calificaciones registradas.")
        return []
        
    encrypted_grades_list = db_grades[student_username]
    decrypted_grades = []
    
    print("-> Calificaciones Descifradas")
    for i, (enc_grade, enc_key, nonce) in enumerate(encrypted_grades_list):
        try:
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade,
                enc_key,
                nonce,
                student_session.private_key 
            )
            print(f"  {i+1}. {grade_str}")
            decrypted_grades.append(grade_str)
        except Exception as e:
            print(f"  {i+1}. ERROR AL DESCIFRAR ESTA NOTA: {e}")
            
    print("\n----------------------------------")
    return decrypted_grades
