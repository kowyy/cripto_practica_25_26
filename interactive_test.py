import user_manager
import grade_system
import getpass  # getpass para ocultar la entrada de contraseñas en el input

def handle_register():
    """Maneja el flujo de registro de un nuevo usuario."""
    print("\n--- Registro de Nuevo Usuario ---")
    username = input("Nombre de usuario: ")
    
    # Usar getpass para que la contraseña no se muestre en pantalla
    password = getpass.getpass("Contraseña: ")
    password_confirm = getpass.getpass("Confirmar contraseña: ")

    if password != password_confirm:
        print("\nERROR: Las contraseñas no coinciden.")
        return

    role = input("Rol (profesor / alumno): ").lower().strip()
    if role not in ['profesor', 'alumno']:
        print(f"\nERROR: Rol '{role}' inválido. Debe ser 'profesor' o 'alumno'.")
        return
    
    try:
        user_manager.register_user(username, password, role)
    except ValueError as e:
        print(f"\nERROR en el registro: {e}")
    except Exception as e:
        print(f"\nERROR inesperado: {e}")

def handle_login():
    """Maneja el flujo de inicio de sesión."""
    print("\n--- Iniciar Sesión ---")
    username = input("Nombre de usuario: ")
    password = getpass.getpass("Contraseña: ")
    
    try:
        session = user_manager.login_user(username, password)
        return session
    except ValueError as e:
        print(f"\nERROR de login: {e}")
        return None
    except Exception as e:
        print(f"\nERROR inesperado: {e}")

def run_professor_menu(session):
    """Muestra el menú para un profesor logueado."""
    while True:
        print(f"\n--- Menú Profesor (Logueado como: {session.username}) ---")
        print("1. Añadir calificación a un alumno")
        print("2. Cerrar sesión")
        choice = input("Seleccione una opción: ")

        if choice == '1':
            handle_add_grade(session)
        elif choice == '2':
            print(f"Cerrando sesión de {session.username}...")
            return  # Vuelve al menú principal
        else:
            print("Opción no válida.")

def handle_add_grade(prof_session):
    """Maneja el flujo para que un profesor añada una nota."""
    print("\n-> Añadir Calificación")
    student_username = input("Nombre de usuario del alumno: ")
    subject = input("Asignatura: ")
    grade = input("Calificación (ej: 9.5 Sobresaliente): ")
    
    try:
        grade_system.add_grade(prof_session, student_username, subject, grade)
    except (PermissionError, ValueError) as e:
        print(f"\nERROR al añadir nota: {e}")
    except Exception as e:
        print(f"\nERROR inesperado: {e}")

def run_student_menu(session):
    """Muestra el menú para un alumno logueado."""
    while True:
        print(f"\n--- Menú Alumno (Logueado como: {session.username}) ---")
        print("1. Ver mis calificaciones")
        print("2. Cerrar sesión")
        choice = input("Seleccione una opción: ")

        if choice == '1':
            handle_view_grades(session)
        elif choice == '2':
            print(f"Cerrando sesión de {session.username}...")
            return  # Vuelve al menú principal
        else:
            print("Opción no válida.")

def handle_view_grades(student_session):
    """Maneja el flujo para que un alumno vea sus notas."""
    try:
        grade_system.view_my_grades(student_session)
    except PermissionError as e:
        print(f"\nERROR al ver notas: {e}")
    except Exception as e:
        print(f"\nERROR inesperado: {e}")


def run_interactive_session():
    """Función principal que ejecuta el bucle del menú interactivo."""
    current_session = None
    print("==============================================")
    print("  BIENVENIDO AL SISTEMA DE CALIFICACIONES ")
    print("==============================================")

    while True:
        if current_session is None:
            # Menú principal (deslogueado)
            print("\n--- Menú Principal ---")
            print("1. Registrar usuario")
            print("2. Iniciar sesión")
            print("3. Salir")
            choice = input("Seleccione una opción: ")
            
            if choice == '1':
                handle_register()
            elif choice == '2':
                current_session = handle_login()
            elif choice == '3':
                print("Saliendo del sistema...")
                break
            else:
                print("Opción no válida.")
        
        elif current_session.role == 'profesor':
            run_professor_menu(current_session)
            current_session = None  # Al salir del menú de rol, se cierra sesión

        elif current_session.role == 'alumno':
            run_student_menu(current_session)
            current_session = None  # Al salir del menú de rol, se cierra sesión
        
        print("\n" + "="*46 + "\n") # Separador

if __name__ == "__main__":
    run_interactive_session()
