import user_manager
import grade_system

def run_simulation():
    """
    Ejecuta una simulación completa del flujo de la aplicación.
    Prueba el registro, login y las operaciones criptográficas.
    """
    print("-> INICIO DE LA SIMULACIÓN DEL SISTEMA DE CALIFICACIONES")

    # Esto es el registro de usuarios, tanto alumno como profesor
    try:
        user_manager.register_user("Jose Maria de Fuentes", "PassProfesor123!", "profesor")
        user_manager.register_user("Adam Kowalczyk", "PassAlumno456!", "alumno")
    except ValueError as e:
        print(f"ERROR: fallo de registro {e}")

    # El profesor añade la note
    print("\n-> Intento de Login (Profesor)")
    try:
        # El profesor inicia sesión
        profesor_session = user_manager.login_user("Jose Maria de Fuentes", "PassProfesor123!")
        
        # El profesor añade notas
        grade_system.add_grade(profesor_session, "Adam Kowalczyk", "Criptografía", "9.5 (Sobresaliente)")
        grade_system.add_grade(profesor_session, "Adam Kowalczyk", "Redes", "7.2 (Notable)")
        
    except ValueError as e:
        print(f"Fallo en el flujo del profesor: {e}")

    # El alumno intenta iniciar sesión y mirar sus notas
    print("\n-> Intento de Login (Alumno)")
    try:
        # El alumno inicia sesión
        alumno_session = user_manager.login_user("Adam Kowalczyk", "PassAlumno456!")
        
        # El alumno ve sus notas
        grade_system.view_my_grades(alumno_session)
        
    except ValueError as e:
        print(f"Fallo en el flujo del alumno: {e}")

    # Probamos como sería un fallo de contraseña incorrecta
    print("\n-> Prueba de Login (Contraseña incorrecta)")
    try:
        user_manager.login_user("Adam Kowalczyk", "contraseña_erronea")
    except ValueError as e:
        print(f"Prueba exitosa: El login falló como se esperaba. ({e})")

    # Probamos como sería un fallo de falta de permisos de parte del alumno
    print("\n-> Prueba de Permisos (Alumno intenta añadir nota)")
    try:
        # Re-login del alumno para tener una sesión válida
        alumno_session_fail = user_manager.login_user("Adam Kowalczyk", "PassAlumno456!")
        grade_system.add_grade(alumno_session_fail, "Jose Maria de Fuentes", "Fallo", "0.0")
    except PermissionError as e:
        print(f"Prueba exitosa: La acción fue denegada como se esperaba. ({e})")
    except ValueError as e:
        print(f"Fallo en prueba de permisos: {e}")
        
    print("\nFIN DE LA SIMULACIÓN")

if __name__ == "__main__":
    run_simulation()
