import datetime
import os
import hashlib
import json

AUDIT_FILE = "audit_system.log"
AUDIT_HASH_FILE = "audit_system.hash"

def compute_file_hash(filename):
    # Calculamos el hash del archivo para saber si ha sido modificado
    if not os.path.exists(filename):
        return None
    
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculando hash: {e}")
        return None

def save_audit_hash():
    # Guardamos el hash actual para compararlo después
    current_hash = compute_file_hash(AUDIT_FILE)
    if current_hash:
        try:
            with open(AUDIT_HASH_FILE, 'w') as f:
                json.dump({
                    'hash': current_hash,
                    'last_update': datetime.datetime.now(datetime.timezone.utc).isoformat()
                }, f)
        except Exception as e:
            print(f"Error guardando hash: {e}")

def verify_audit_integrity():
    # Comprobamos si el hash actual coincide con el guardado
    if not os.path.exists(AUDIT_FILE):
        return True
    
    if not os.path.exists(AUDIT_HASH_FILE):
        print("Aviso: No hay hash de referencia, se generará uno nuevo.")
        save_audit_hash()
        return True
    
    try:
        with open(AUDIT_HASH_FILE, 'r') as f:
            stored_data = json.load(f)
            stored_hash = stored_data.get('hash')
        
        current_hash = compute_file_hash(AUDIT_FILE)
        
        if current_hash != stored_hash:
            print("\nALERTA DE SEGURIDAD")
            print("El archivo de auditoría ha sido modificado externamente.")
            print(f"Hash esperado: {stored_hash}")
            print(f"Hash actual:   {current_hash}")
            return False
        
        return True
        
    except Exception as e:
        print(f"Error verificando integridad: {e}")
        return False

def log_event(actor, action, target, status="SUCCESS"):
    # Guardamos un evento en el log y actualizamos el hash
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    entry = (f"[{timestamp}] "
             f"Actor: {actor:20} | "
             f"Action: {action:20} | "
             f"Target: {target:20} | "
             f"Status: {status}\n")
    
    try:
        # Primero verificamos que nadie haya tocado el archivo
        verify_audit_integrity()
        
        with open(AUDIT_FILE, "a", encoding='utf-8') as f:
            f.write(entry)
        
        # Guardamos el nuevo hash
        save_audit_hash()
        
    except Exception as e:
        print(f"Error crítico al escribir en log: {e}")

def read_logs(verify_integrity=True):
    # Mostramos los logs por pantalla
    if not os.path.exists(AUDIT_FILE):
        print("\nRegistro de auditoría")
        print("Vacío.")
        return
    
    if verify_integrity:
        is_valid = verify_audit_integrity()
        if not is_valid:
            print("Aviso: El log podría estar manipulado.")
    
    print("\nRegistro de auditoría del sistema")
    
    try:
        with open(AUDIT_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
            if content.strip():
                print(content)
            else:
                print("Vacío.")
    except Exception as e:
        print(f"Error leyendo log: {e}")

def search_logs(actor=None, action=None, target=None, status=None):
    # Buscamos eventos específicos
    if not os.path.exists(AUDIT_FILE):
        print("No hay registros.")
        return
    
    print("\nBúsqueda en auditoría")
    
    filters = []
    if actor: filters.append(f"Actor: {actor}")
    if action: filters.append(f"Action: {action}")
    if target: filters.append(f"Target: {target}")
    if status: filters.append(f"Status: {status}")
    
    print(f"Filtrando por: {', '.join(filters) if filters else 'Todo'}")
    
    try:
        found = 0
        with open(AUDIT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                match = True
                if actor and f"Actor: {actor}" not in line:
                    match = False
                if action and f"Action: {action}" not in line:
                    match = False
                if target and f"Target: {target}" not in line:
                    match = False
                if status and f"Status: {status}" not in line:
                    match = False
                
                if match:
                    print(line.strip())
                    found += 1
        
        print(f"\nSe encontraron {found} registros.")
        
    except Exception as e:
        print(f"Error buscando: {e}")

def clear_audit_log():
    # Borramos el log
    try:
        if os.path.exists(AUDIT_FILE):
            os.remove(AUDIT_FILE)
        if os.path.exists(AUDIT_HASH_FILE):
            os.remove(AUDIT_HASH_FILE)
        print("Log de auditoría borrado.")
    except Exception as e:
        print(f"Error limpiando log: {e}")
