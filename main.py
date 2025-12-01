import os
import shutil
import user_manager
import grade_system
import audit_log

def reset_system():
    # Esta función borra todos los archivos generados para empezar de cero las pruebas
    files_to_remove = [
        "users_db.json", 
        "users_db.json.tmp",
        "grades_db.json",
        "grades_db.json.tmp",
        "audit_system.log",
        "audit_system.hash"
    ]
    
    dirs_to_remove = ["pki_store"]
    
    print("\nIniciando limpieza del sistema...")
    
    # Borramos los archivos
    for filename in files_to_remove:
        if os.path.exists(filename):
            try:
                os.remove(filename)
                print(f"Archivo eliminado: {filename}")
            except Exception as e:
                print(f"No se pudo eliminar {filename}: {e}")
    
    # Borramos los directorios
    for dirname in dirs_to_remove:
        if os.path.exists(dirname):
            try:
                shutil.rmtree(dirname)
                print(f"Directorio eliminado: {dirname}")
            except Exception as e:
                print(f"No se pudo eliminar {dirname}: {e}")

    # Limpiamos las variables en memoria
    user_manager.db_users.clear()
    grade_system.db_grades.clear()
    print("Memoria limpiada.")
    print("Sistema reiniciado correctamente.\n")

def run_simulation():
    # Ejecutamos una demostración automática de todo el flujo del sistema
    
    print("\nSimulación automática del sistema")
    
    # Primero limpiamos todo
    reset_system()
    
    print("\nFase de registro y generación de claves")
    
    # Registramos a los usuarios de prueba
    try:
        print("\nRegistrando al profesor...")
        user_manager.register_user(
            "Jose Maria de Fuentes", 
            "ProfesorSeguro123!", 
            "profesor"
        )
        
        print("\nRegistrando al alumno...")
        user_manager.register_user(
            "Adam Kowalczyk", 
            "AlumnoSeguro456!", 
            "alumno"
        )
        
        print("\nUsuarios registrados y certificados emitidos.")
        
    except ValueError as e:
        print(f"\nError en el registro: {e}")
        return
    except Exception as e:
        print(f"\nError inesperado: {e}")
        return
    
    # El profesor entra y pone notas
    print("\nFase del profesor: Firmar y cifrar notas")
    
    try:
        print("\nIniciando sesión del profesor...")
        profesor_session = user_manager.login_user(
            "Jose Maria de Fuentes", 
            "ProfesorSeguro123!"
        )
        
        print("\nAñadiendo calificaciones...")
        
        grade_system.add_grade(
            profesor_session, 
            "Adam Kowalczyk", 
            "Criptografía", 
            "9.5 (Sobresaliente)"
        )
        
        grade_system.add_grade(
            profesor_session, 
            "Adam Kowalczyk", 
            "Redes", 
            "7.2 (Notable)"
        )
        
        grade_system.add_grade(
            profesor_session,
            "Adam Kowalczyk",
            "Seguridad Informática",
            "8.7 (Notable Alto)"
        )
        
        print("\nCalificaciones guardadas.")
        
    except Exception as e:
        print(f"\nError en la fase del profesor: {e}")
        return
    
    # El alumno entra y ve sus notas
    print("\nFase del alumno: Verificar firmas y descifrar")
    
    try:
        print("\nIniciando sesión del alumno...")
        alumno_session = user_manager.login_user(
            "Adam Kowalczyk", 
            "AlumnoSeguro456!"
        )
        
        print("\nConsultando notas...")
        
        grade_system.view_my_grades(alumno_session)
        
    except Exception as e:
        print(f"\nError en la fase del alumno: {e}")
        return
    
    # Probamos que la seguridad funciona forzando errores
    print("\nFase de pruebas de seguridad")
    
    print("\nPrueba: Login con contraseña mal")
    try:
        user_manager.login_user("Adam Kowalczyk", "contraseña_erronea")
        print("Fallo: El sistema debería haber bloqueado el acceso")
    except ValueError as e:
        print(f"Correcto: Acceso bloqueado. Mensaje: {e}")
    
    print("\nPrueba: Alumno intenta poner notas")
    try:
        alumno_session_test = user_manager.login_user("Adam Kowalczyk", "AlumnoSeguro456!")
        grade_system.add_grade(
            alumno_session_test, 
            "Jose Maria de Fuentes", 
            "Hackeo", 
            "10.0"
        )
        print("Fallo: El sistema permitió la acción")
    except PermissionError as e:
        print(f"Correcto: Acción denegada. Mensaje: {e}")
    except Exception as e:
        print(f"Resultado inesperado: {e}")
    
    print("\nPrueba: Contraseña débil")
    try:
        user_manager.register_user("Usuario Test", "123", "alumno")
        print("Fallo: Se aceptó una contraseña débil")
    except ValueError as e:
        print(f"Correcto: Contraseña rechazada. Mensaje: {e}")
    
    print("\nPrueba: Integridad del log")
    is_valid = audit_log.verify_audit_integrity()
    if is_valid:
        print("Correcto: El log está íntegro")
    else:
        print("Alerta: El log parece modificado")
    
    print("\nSimulación finalizada")

def show_menu():
    # Menú principal de la aplicación
    print("\nSistema de Gestión de Notas")
    print("Opciones disponibles:")
    print("1. Ejecutar simulación automática")
    print("2. Modo interactivo manual")
    print("3. Ver registros de auditoría")
    print("4. Reiniciar todo el sistema")
    print("5. Salir")

if __name__ == "__main__":
    try:
        while True:
            show_menu()
            choice = input("\nElija una opción: ").strip()
            
            if choice == '1':
                run_simulation()
                input("\nPulse Enter para seguir...")
                
            elif choice == '2':
                print("\nAbriendo modo interactivo...")
                import interactive_test
                interactive_test.run_interactive_session()
                
            elif choice == '3':
                audit_log.read_logs()
                input("\nPulse Enter para seguir...")
                
            elif choice == '4':
                confirm = input("\nSeguro que quiere borrar todo el sistema? (s/n): ")
                if confirm.lower() == 's':
                    reset_system()
                    input("\nPulse Enter para seguir...")
                else:
                    print("Cancelado.")
                    
            elif choice == '5':
                print("\nAdiós.")
                break
                
            else:
                print("\nOpción no válida.")
    
    except KeyboardInterrupt:
        print("\nSaliendo...")
    except Exception as e:
        print(f"\nError crítico: {e}")
