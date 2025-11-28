import os
import json
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PKI_DIR = "pki_store"
ROOT_KEY_FILE = os.path.join(PKI_DIR, "root_ca_key.pem")
ROOT_CERT_FILE = os.path.join(PKI_DIR, "root_ca_cert.pem")
SUB_KEY_FILE = os.path.join(PKI_DIR, "sub_ca_key.pem")
SUB_CERT_FILE = os.path.join(PKI_DIR, "sub_ca_cert.pem")
CRL_FILE = os.path.join(PKI_DIR, "crl.json") # Lista de Revocación simulada

def ensure_pki_dir_exists():
    if not os.path.exists(PKI_DIR):
        os.makedirs(PKI_DIR)

def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def load_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(filename):
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_crl():
    if not os.path.exists(CRL_FILE):
        return []
    try:
        with open(CRL_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_crl(revoked_list):
    with open(CRL_FILE, 'w') as f:
        json.dump(revoked_list, f, indent=4)

def revoke_certificate(cert_pem):
    """Añade el número de serie de un certificado a la CRL."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        serial = cert.serial_number
        
        crl = load_crl()
        if serial not in crl:
            crl.append(serial)
            save_crl(crl)
            print(f"DEBUG [PKI]: Certificado {serial} REVOCADO correctamente.")
    except Exception as e:
        print(f"ERROR [PKI]: Fallo al revocar certificado: {e}")

def is_revoked(cert):
    """Comprueba si un certificado está en la CRL."""
    crl = load_crl()
    return cert.serial_number in crl

def setup_pki():
    """
    Inicializa la PKI. 
    Simula protección de Root CA: solo carga la clave raíz si es estrictamente necesario 
    para firmar la Sub CA, luego la 'olvida'.
    """
    ensure_pki_dir_exists()

    if os.path.exists(ROOT_CERT_FILE) and os.path.exists(SUB_CERT_FILE):
        return

    print("INFO: Generando PKI (Root CA offline + Sub CA online)...")

    # 1. Generar Root CA (Operación sensible)
    root_key = generate_private_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UC3M Root CA"),
    ])
    root_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        root_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256())

    save_key(root_key, ROOT_KEY_FILE)
    save_cert(root_cert, ROOT_CERT_FILE)
    
    # 2. Generar Sub CA firmada por Root
    sub_key = generate_private_key()
    sub_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"UC3M Sub CA - Grados"),
    ])
    sub_cert = x509.CertificateBuilder().subject_name(sub_subject).issuer_name(root_cert.subject).public_key(
        sub_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    ).sign(root_key, hashes.SHA256()) # Firma con Root Key

    save_key(sub_key, SUB_KEY_FILE)
    save_cert(sub_cert, SUB_CERT_FILE)
    
    # "Borrado" de memoria de la clave raíz
    del root_key 
    print("INFO: Clave Root CA descargada de memoria (Seguridad Offline).")

def issue_user_certificate(user_public_key, username, role):
    """Emite certificado de usuario usando solo la Sub CA."""
    setup_pki()
    
    sub_key = load_key(SUB_KEY_FILE)
    sub_cert = load_cert(SUB_CERT_FILE)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"Rol: {role}"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(sub_cert.subject).public_key(
        user_public_key
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(sub_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem):
    """Valida firma, fechas y ESTADO DE REVOCACIÓN (CRL)."""
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        sub_cert = load_cert(SUB_CERT_FILE)
        
        if is_revoked(user_cert):
            raise Exception(f"Certificado REVOCADO (Serial: {user_cert.serial_number})")

        sub_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), 
            user_cert.signature_hash_algorithm
        )
        
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
            raise Exception("Certificado caducado o aún no válido")

        return True
    except Exception as e:
        print(f"ALERTA SEGURIDAD [PKI]: {e}")
        return False
