import os
import json
import datetime
import getpass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PKI_DIR = "pki_store"
ROOT_KEY_FILE = os.path.join(PKI_DIR, "root_ca_key.pem")
ROOT_CERT_FILE = os.path.join(PKI_DIR, "root_ca_cert.pem")
SUB_KEY_FILE = os.path.join(PKI_DIR, "sub_ca_key.pem")
SUB_CERT_FILE = os.path.join(PKI_DIR, "sub_ca_cert.pem")
CRL_FILE = os.path.join(PKI_DIR, "crl.json")

def ensure_pki_dir_exists():
    if not os.path.exists(PKI_DIR):
        os.makedirs(PKI_DIR)
        print(f"INFO: Directorio {PKI_DIR} creado.")

def generate_private_key():
    # Creamos una clave RSA estándar
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key_encrypted(key, filename, password=None):
    # Guardamos la clave cifrada con contraseña por seguridad
    if password is None:
        print(f"\nSe necesita contraseña para: {filename}")
        password = getpass.getpass("Contraseña para cifrar: ")
        confirm = getpass.getpass("Confirme contraseña: ")
        
        if password != confirm:
            raise ValueError("Las contraseñas no coinciden")
    
    encryption = serialization.BestAvailableEncryption(password.encode())
    
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ))
    print(f"INFO: Clave guardada en {filename}")

def load_key_encrypted(filename, password=None):
    # Cargamos una clave cifrada
    if password is None:
        password = getpass.getpass(f"Contraseña para {filename}: ")
    
    try:
        with open(filename, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), 
                password=password.encode()
            )
    except Exception as e:
        raise ValueError(f"No se pudo cargar la clave: {e}")

def save_cert(cert, filename):
    # Guardamos el certificado público
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(filename):
    # Leemos el certificado
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_crl():
    # Leemos la lista de certificados revocados
    if not os.path.exists(CRL_FILE):
        return []
    try:
        with open(CRL_FILE, 'r') as f:
            data = json.load(f)
            if not isinstance(data, list):
                print("Aviso: CRL corrupta, se reinicia.")
                return []
            return data
    except Exception as e:
        print(f"Error cargando CRL: {e}")
        return []

def save_crl(revoked_list):
    # Guardamos la lista de revocación de forma segura
    ensure_pki_dir_exists()
    temp_file = CRL_FILE + ".tmp"
    
    try:
        with open(temp_file, 'w') as f:
            json.dump(revoked_list, f, indent=4)
        
        os.replace(temp_file, CRL_FILE)
    except Exception as e:
        print(f"Error guardando CRL: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)

def revoke_certificate(cert_pem):
    # Añadimos un certificado a la lista negra
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial = cert.serial_number
        
        crl = load_crl()
        
        for entry in crl:
            if entry.get('serial') == serial:
                print(f"INFO: El certificado {serial} ya estaba revocado.")
                return
        
        revocation_entry = {
            'serial': serial,
            'revoked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'reason': 'user_deletion'
        }
        
        crl.append(revocation_entry)
        save_crl(crl)
        
        print(f"DEBUG: Certificado {serial} revocado.")
    except Exception as e:
        print(f"Error al revocar: {e}")

def is_revoked(cert):
    # Comprobamos si el certificado está en la lista negra
    crl = load_crl()
    serial = cert.serial_number
    
    for entry in crl:
        if entry.get('serial') == serial:
            return True, entry.get('revoked_at', 'unknown')
    
    return False, None

def setup_pki():
    # Preparamos las autoridades de certificación
    ensure_pki_dir_exists()

    if os.path.exists(ROOT_CERT_FILE) and os.path.exists(SUB_CERT_FILE):
        print("INFO: PKI ya está lista.")
        return

    print("\nInicializando Autoridades de Certificación")
    print("La clave Raíz se cifrará. Esta contraseña es importante.")
    
    # Creamos la CA Raíz
    root_key = generate_private_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UC3M Root CA"),
    ])
    
    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256())

    save_key_encrypted(root_key, ROOT_KEY_FILE)
    save_cert(root_cert, ROOT_CERT_FILE)
    
    # Creamos la Sub CA firmada por la Raíz
    print("\nGenerando Sub CA")
    
    sub_key = generate_private_key()
    sub_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UC3M Sub CA - Grados"),
    ])
    
    sub_cert = x509.CertificateBuilder().subject_name(
        sub_subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        sub_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    ).sign(root_key, hashes.SHA256())

    save_key_encrypted(sub_key, SUB_KEY_FILE)
    save_cert(sub_cert, SUB_CERT_FILE)
    
    # Borramos las claves de memoria
    del root_key
    del sub_key
    
    print("\nPKI generada.")
    print(f"Recomendación: Puede eliminar {ROOT_KEY_FILE} para simular almacenamiento offline.\n")

def issue_user_certificate(user_public_key, username, role):
    # Emitimos un certificado para un usuario nuevo
    setup_pki()
    
    sub_key = load_key_encrypted(SUB_KEY_FILE)
    sub_cert = load_cert(SUB_CERT_FILE)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Rol: {role}"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        sub_cert.subject
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(sub_key, hashes.SHA256())

    print(f"INFO: Certificado creado para {username}")
    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem):
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        sub_cert = load_cert(SUB_CERT_FILE)
        root_cert = load_cert(ROOT_CERT_FILE)
        
        # Check revocation
        revoked, revoked_at = is_revoked(user_cert)
        if revoked:
            raise Exception(f"Certificado revocado en fecha {revoked_at}")
        
        # Verify User Cert is signed by Sub CA
        sub_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), 
            user_cert.signature_hash_algorithm
        )
        print(f"DEBUG: User cert signed by Sub CA ✓")
        
        # Verify Sub CA is signed by Root CA
        root_cert.public_key().verify(
            sub_cert.signature,
            sub_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            sub_cert.signature_hash_algorithm
        )
        print(f"DEBUG: Sub CA signed by Root CA ✓")
        
        # Verify Root CA is self-signed (trust anchor)
        root_cert.public_key().verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm
        )
        print(f"DEBUG: Root CA self-signed ✓")
        
        # Check validity dates for entire chain
        now = datetime.datetime.now(datetime.timezone.utc)
        
        for cert, name in [(user_cert, "User"), (sub_cert, "Sub CA"), (root_cert, "Root CA")]:
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                raise Exception(f"{name} certificate expired or not yet valid")
        
        print(f"DEBUG: Full certificate chain verified ✓")
        return True
        
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False
