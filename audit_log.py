import datetime
import os

AUDIT_FILE = "audit_system.log"

def log_event(actor, action, target, status="SUCCESS"):
    """
    Registra un evento en el log de auditoría inmutable.
    Formato: [TIMESTAMP] [ACTOR] [ACCION] [OBJETIVO] -> [ESTADO]
    """
    timestamp = datetime.datetime.now().isoformat()
    entry = f"[{timestamp}] User:{actor} | Action:{action} | Target:{target} | Status:{status}\n"
    
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(entry)
    except Exception as e:
        print(f"ERROR CRÍTICO: No se pudo escribir en el log de auditoría: {e}")

def read_logs():
    if not os.path.exists(AUDIT_FILE):
        print("No hay registros de auditoría.")
        return
    print("\n--- REGISTRO DE AUDITORÍA DEL SISTEMA ---")
    with open(AUDIT_FILE, 'r') as f:
        print(f.read())
    print("-----------------------------------------\n")
