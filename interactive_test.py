import user_manager
import grade_system
import getpass

def handle_register():
    print("\n--- Registro (Con Certificado Digital) ---")
    username = input("Usuario: ")
    password = getpass.getpass("Contraseña: ")
    role = input("Rol (profesor/alumno): ").lower().strip()
    
    try:
        user_manager.register_user(username, password, role)
    except Exception as e:
        print(f"Error: {e}")

def handle_login():
    print("\n--- Login ---")
    username = input("Usuario: ")
    password = getpass.getpass("Contraseña: ")
    try:
        return user_manager.login_user(username, password)
    except Exception as e:
        print(f"Error Login: {e}")
        return None

def handle_add_grade(prof_session):
    print("\n-> Nueva Calificación")
    stu = input("Alumno: ")
    sub = input("Asignatura: ")
    val = input("Nota: ")
    try:
        grade_system.add_grade(prof_session, stu, sub, val)
    except Exception as e:
        print(f"Error: {e}")

def handle_modify_grade(prof_session):
    print("\n-> Modificar Calificación")
    stu = input("Alumno a consultar: ")
    
    # 1. Listar notas visibles para el profesor
    grades = grade_system.view_grades_professor(prof_session, stu)
    if not grades:
        return

    # 2. Seleccionar
    try:
        idx_str = input("Introduce el ID (número entre corchetes) de la nota a cambiar: ")
        idx = int(idx_str)
    except ValueError:
        print("ID inválido.")
        return

    # 3. Datos nuevos
    print("Introduce los nuevos datos completos:")
    sub = input("Asignatura (Corrección): ")
    val = input("Nota (Corrección): ")
    new_str = f"Asignatura: {sub} | Calificación: {val}"
    
    try:
        grade_system.modify_grade(prof_session, stu, idx, new_str)
    except Exception as e:
        print(f"Error al modificar: {e}")

def run_interactive_session():
    session = None
    print("=== SISTEMA DE NOTAS SEGURO ===")

    while True:
        if not session:
            print("\n1. Registrar\n2. Login\n3. Salir")
            opt = input("> ")
            if opt == '1': handle_register()
            elif opt == '2': session = handle_login()
            elif opt == '3': break
        
        elif session.role == 'profesor':
            print(f"\nProfesor: {session.username}")
            print("1. Poner Nota")
            print("2. Ver/Modificar Notas de Alumno")
            print("3. Logout")
            opt = input("> ")
            if opt == '1': handle_add_grade(session)
            elif opt == '2': handle_modify_grade(session)
            elif opt == '3': session = None
            
        elif session.role == 'alumno':
            print(f"\nAlumno: {session.username}")
            print("1. Ver mis notas")
            print("2. Logout")
            opt = input("> ")
            if opt == '1': grade_system.view_my_grades(session)
            elif opt == '2': session = None

if __name__ == "__main__":
    run_interactive_session()
