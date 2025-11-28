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

def handle_delete_grade(prof_session):
    """Flujo para que el profesor borre una nota."""
    print("\n-> Borrar Calificación")
    stu = input("Alumno a consultar: ")
    
    grades = grade_system.view_grades_professor(prof_session, stu)
    if not grades:
        return

    print("\n[?] Escribe el ID de la nota para BORRARLA.")
    choice = input("ID > ")
    
    try:
        idx = int(choice)
        grade_system.delete_grade(prof_session, stu, idx)
    except ValueError:
        print("Error: ID inválido.")
    except Exception as e:
        print(f"Error: {e}")

def handle_delete_user():
    """Flujo para borrar un usuario y sus datos asociados."""
    print("\n--- Borrar Usuario del Sistema (y sus datos) ---")
    username = input("Nombre del usuario a eliminar: ")
    
    confirm = input(f"¿ATENCIÓN: Se borrarán '{username}' y TODAS sus notas. ¿Continuar? (s/n): ")
    if confirm.lower() != 's':
        print("Operación cancelada.")
        return

    try:
        user_manager.delete_user(username)
        
        grade_system.delete_all_grades_of_student(username)
        
        print("\n>>> Proceso de eliminación completado exitosamente.")
        
    except Exception as e:
        print(f"Error durante el borrado: {e}")

def handle_modify_grade(prof_session):
    print("\n-> Modificar Calificación")
    stu = input("Alumno a consultar (o pulsa Enter para cancelar): ")
    if not stu.strip():
        return
    
    # Listar notas visibles para el profesor
    grades = grade_system.view_grades_professor(prof_session, stu)
    if not grades:
        return

    print("\n[?] Escribe el ID de la nota para modificarla.")
    print("    O escribe 's' (o 'salir') para volver al menú.")
    
    choice = input("Selección > ")
    
    if choice.lower() in ['s', 'salir', 'exit', 'q']:
        print("Operación cancelada. Volviendo al menú...")
        return

    try:
        idx = int(choice)
    except ValueError:
        print("Error: Debes introducir un número válido o 's' para salir.")
        return

    # Datos nuevos
    print(f"\nModificando nota ID [{idx}] de {stu}...")
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
            print("\n--- Menú Principal ---")
            print("1. Registrar usuario")
            print("2. Iniciar sesión")
            print("3. Borrar usuario (Admin)")
            print("4. Salir")
            opt = input("Opción > ")
            
            if opt == '1': handle_register()
            elif opt == '2': session = handle_login()
            elif opt == '3': handle_delete_user()
            elif opt == '4': break
            else: print("Opción no válida.")
        
        elif session.role == 'profesor':
            print(f"\n--- Panel Profesor: {session.username} ---")
            print("1. Poner Nota")
            print("2. Ver/Modificar Notas de Alumno")
            print("3. Borrar Nota")
            print("4. Logout")
            opt = input("Opción > ")
            
            if opt == '1': handle_add_grade(session)
            elif opt == '2': handle_modify_grade(session)
            elif opt == '3': handle_delete_grade(session)
            elif opt == '4': session = None
            
        elif session.role == 'alumno':
            print(f"\n--- Panel Alumno: {session.username} ---")
            print("1. Ver mis notas")
            print("2. Logout")
            opt = input("Opción > ")
            
            if opt == '1': grade_system.view_my_grades(session)
            elif opt == '2': session = None

if __name__ == "__main__":
    run_interactive_session()
