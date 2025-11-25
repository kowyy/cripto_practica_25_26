import user_manager
import crypto_manager

# Simulación de la base de datos de calificaciones
# Almacena tuplas cifradas
db_grades = {} # { 'username_alumno': [ (enc_grade, enc_key, nonce), ... ] }

def add_grade(professor_session, student_username, subject, grade):
    """
    Profesor añade una nueva calificación cifrada para un alumno.
    """
    # Verifiación de permisos simple
    if professor_session.role != 'profesor':
        raise PermissionError("Acción no autorizada. Solo los profesores pueden añadir notas.")
        
    print(f"\nACCIÓN: Profesor '{professor_session.username}' añade nota para '{student_username}'...")
    
    # Obtener clave pública del destinatario (alumno)
    try:
        student_public_key_pem = user_manager.get_public_key_pem(student_username)
    except ValueError:
        print(f"ERROR: El estudiante '{student_username}' no existe.")
        return

    # Formatear y cifrar los datos
    grade_data_str = f"Asignatura: {subject} | Calificación: {grade}"
    
    encrypted_grade, encrypted_sym_key, nonce = \
        crypto_manager.encrypt_grade_hybrid(grade_data_str, student_public_key_pem)
        
    # Almacenar en la base de datos
    if student_username not in db_grades:
        db_grades[student_username] = []
        
    db_grades[student_username].append(
        (encrypted_grade, encrypted_sym_key, nonce)
    )
    print(f"INFO: Calificación cifrada y almacenada para '{student_username}'.")

def view_my_grades(student_session):
    """
    El alumno ve todas sus calificaciones descifradas.
    """
    # Verificación de permisos
    if student_session.role != 'alumno':
        raise PermissionError("Acción no autorizada. Solo los alumnos pueden ver sus notas.")
        
    print(f"\nAlumno '{student_session.username}' solicita ver sus notas...")
    
    # Obtener datos cifrados
    student_username = student_session.username
    if student_username not in db_grades or not db_grades[student_username]:
        print("INFO: No tienes calificaciones registradas.")
        return []
        
    encrypted_grades_list = db_grades[student_username]
    decrypted_grades = []
    
    # Descifrar cada calificación
    print("-> Calificaciones Descifradas")
    for i, (enc_grade, enc_key, nonce) in enumerate(encrypted_grades_list):
        try:
            grade_str = crypto_manager.decrypt_grade_hybrid(
                enc_grade,
                enc_key,
                nonce,
                student_session.private_key # Usa su clave privada descifrada
            )
            print(f"  {i+1}. {grade_str}")
            decrypted_grades.append(grade_str)
        except Exception as e:
            print(f"  {i+1}. ERROR AL DESCIFRAR ESTA NOTA: {e}")
            
    print("\n----------------------------------")
    return decrypted_grades
