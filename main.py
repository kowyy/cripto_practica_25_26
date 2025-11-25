import os
import shutil
import user_manager
import grade_system

def reset_system():
    """
    Borra la base de datos y la PKI para iniciar una simulación limpia.
    """
    files_to_remove = ["users_db.json", "grades_db.json"]
    dirs_to_remove = ["pki_store"]
    
    print("--- LIMPIEZA DE ENTORNO (RESET) ---")
    
    # 1. Limpiar Disco
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)
            print(f"Eliminado: {f}")
            
    for d in dirs_to_remove:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"Eliminado directorio: {d}")

    # 2. Limpiar Memoria RAM
    user_manager.db_users = {}
    grade_system.db_grades = {}
    print("Memoria de módulos purgada.")
    
    print("-----------------------------------")

def run_simulation():
    """
    Ejecuta una simulación completa del flujo de la aplicación con PKI y Persistencia.
    """
    # 1. Limpiar entorno previo para demostrar la creación de la PKI
    reset_system()

    print("-> INICIO DE LA SIMULACIÓN (EVAL 2: PKI + FIRMA DIGITAL)")

    # 2. Registro (Aquí se verá la emisión de certificados X.509)
    print("\n[!] Registrando usuarios en la Autoridad de Certificación...")
    try:
        user_manager.register_user("Jose Maria de Fuentes", "PassProfesor123!", "profesor")
        user_manager.register_user("Adam Kowalczyk", "PassAlumno456!", "alumno")
    except ValueError as e:
        print(f"ERROR: fallo de registro {e}")

    # 3. Flujo del Profesor (Firma y Cifrado)
    print("\n-> Intento de Login y Calificación (Profesor)")
    try:
        # Login (carga certificado y clave privada)
        profesor_session = user_manager.login_user("Jose Maria de Fuentes", "PassProfesor123!")
        
        # Añadir notas (Firma Digital RSA-PSS + Cifrado Híbrido)
        grade_system.add_grade(profesor_session, "Adam Kowalczyk", "Criptografía", "9.5 (Sobresaliente)")
        grade_system.add_grade(profesor_session, "Adam Kowalczyk", "Redes", "7.2 (Notable)")
        
    except Exception as e:
        print(f"Fallo en el flujo del profesor: {e}")

    # 4. Flujo del Alumno (Verificación de Firma y PKI)
    print("\n-> Intento de Login y Consulta (Alumno)")
    try:
        # Login
        alumno_session = user_manager.login_user("Adam Kowalczyk", "PassAlumno456!")
        
        # Ver notas (Validación de Certificados y Firmas)
        grade_system.view_my_grades(alumno_session)
        
    except Exception as e:
        print(f"Fallo en el flujo del alumno: {e}")

    # 5. Pruebas de Seguridad (Errores esperados)
    print("\n-> Prueba de Seguridad: Login con contraseña incorrecta")
    try:
        user_manager.login_user("Adam Kowalczyk", "contraseña_erronea")
    except ValueError as e:
        print(f"  [OK] El sistema bloqueó el acceso: {e}")

    print("\n-> Prueba de Seguridad: Alumno intenta firmar nota (Falsificación)")
    try:
        alumno_session_fail = user_manager.login_user("Adam Kowalczyk", "PassAlumno456!")
        grade_system.add_grade(alumno_session_fail, "Jose Maria de Fuentes", "Hackeo", "10.0")
    except PermissionError as e:
        print(f"  [OK] El sistema denegó la acción: {e}")
    except Exception as e:
        print(f"Fallo inesperado: {e}")
        
    print("\nFIN DE LA SIMULACIÓN")

if __name__ == "__main__":
    run_simulation()
