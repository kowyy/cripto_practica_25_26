import user_manager
import grade_system
import audit_log
import getpass

def handle_register():
    print("\nRegistro de nuevo usuario")
    
    username = input("Nombre de usuario: ").strip()
    if not username:
        print("El nombre no puede estar vacío.")
        return
    
    password = getpass.getpass("Contraseña: ")
    password_confirm = getpass.getpass("Confirmar contraseña: ")
    
    if password != password_confirm:
        print("Las contraseñas no coinciden.")
        return
    
    print("\nRoles disponibles: profesor, alumno")
    role = input("Rol: ").lower().strip()
    
    try:
        user_manager.register_user(username, password, role)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")

def handle_login():
    print("\nInicio de sesión")
    
    username = input("Usuario: ").strip()
    if not username:
        return None
    
    password = getpass.getpass("Contraseña: ")
    
    try:
        session = user_manager.login_user(username, password)
        return session
    except ValueError as e:
        print(f"Error de acceso: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def handle_add_grade(prof_session):
    print("\nNueva calificación")
    
    user_manager.list_all_users()
    
    student = input("Alumno: ").strip()
    if not student: return
    
    subject = input("Asignatura: ").strip()
    grade = input("Calificación: ").strip()
    
    if not subject or not grade:
        print("Faltan datos.")
        return
    
    try:
        grade_system.add_grade(prof_session, student, subject, grade)
    except Exception as e:
        print(f"Error: {e}")

def handle_view_and_modify_grade(prof_session):
    print("\nVer y modificar notas")
    
    student = input("Alumno: ").strip()
    if not student: return
    
    grades = grade_system.view_grades_professor(prof_session, student)
    
    if not grades: return
    
    print("\nEscriba el número de la nota para modificarla o pulse Enter para volver.")
    choice = input("Opción: ").strip()
    
    if not choice: return
    
    try:
        idx = int(choice)
        print(f"Modificando nota {idx}...")
        subject = input("Nueva asignatura: ").strip()
        grade_value = input("Nueva nota: ").strip()
        
        new_str = f"Asignatura: {subject} | Calificación: {grade_value}"
        grade_system.modify_grade(prof_session, student, idx, new_str)
        
    except ValueError:
        print("Número inválido.")
    except Exception as e:
        print(f"Error: {e}")

def handle_delete_grade(prof_session):
    print("\nBorrar calificación")
    student = input("Alumno: ").strip()
    if not student: return
    
    grades = grade_system.view_grades_professor(prof_session, student)
    if not grades: return
    
    choice = input("Número de nota a borrar: ").strip()
    if not choice: return
    
    try:
        idx = int(choice)
        confirm = input("¿Seguro? (s/n): ").lower()
        if confirm == 's':
            grade_system.delete_grade(prof_session, student, idx)
    except Exception as e:
        print(f"Error: {e}")

def handle_delete_user():
    print("\nEliminar usuario")
    print("Atención: Esto borra el usuario, sus notas y revoca su certificado.")
    
    user_manager.list_all_users()
    username = input("Usuario a borrar: ").strip()
    
    if not username: return
    
    confirm = input(f"¿Confirma eliminar a {username}? (s/n): ").lower()
    if confirm == 's':
        try:
            user_manager.delete_user(username)
            grade_system.delete_all_grades_of_student(username)
            print("Eliminado.")
        except Exception as e:
            print(f"Error: {e}")

def handle_view_audit_log():
    print("\nLog de auditoría")
    print("1. Ver todo")
    print("2. Buscar")
    choice = input("Opción: ").strip()
    
    if choice == '1':
        audit_log.read_logs()
    elif choice == '2':
        actor = input("Actor (opcional): ").strip()
        audit_log.search_logs(actor=actor or None)

def run_interactive_session():
    session = None
    print("\nSistema de Gestión de Notas")
    
    while True:
        if not session:
            print("\nMenú Principal")
            print("1. Registro")
            print("2. Login")
            print("3. Log de auditoría")
            print("4. Borrar usuario")
            print("5. Salir")
            
            opt = input("Opción: ").strip()
            
            if opt == '1': handle_register()
            elif opt == '2': session = handle_login()
            elif opt == '3': handle_view_audit_log()
            elif opt == '4': handle_delete_user()
            elif opt == '5': break
        
        elif session.role == 'profesor':
            print(f"\nProfesor: {session.username}")
            print("1. Añadir nota")
            print("2. Modificar nota")
            print("3. Borrar nota")
            print("4. Auditoría")
            print("5. Cerrar sesión")
            
            opt = input("Opción: ").strip()
            
            if opt == '1': handle_add_grade(session)
            elif opt == '2': handle_view_and_modify_grade(session)
            elif opt == '3': handle_delete_grade(session)
            elif opt == '4': handle_view_audit_log()
            elif opt == '5': session = None
        
        elif session.role == 'alumno':
            print(f"\nAlumno: {session.username}")
            print("1. Ver notas")
            print("2. Auditoría")
            print("3. Cerrar sesión")
            
            opt = input("Opción: ").strip()
            
            if opt == '1': grade_system.view_my_grades(session)
            elif opt == '2': handle_view_audit_log()
            elif opt == '3': session = None

if __name__ == "__main__":
    try:
        run_interactive_session()
    except KeyboardInterrupt:
        print("\nSaliendo...")
