import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Directorio para almacenar las claves de las CAs
PKI_DIR = "pki_store"
ROOT_KEY_FILE = os.path.join(PKI_DIR, "root_ca_key.pem")
ROOT_CERT_FILE = os.path.join(PKI_DIR, "root_ca_cert.pem")
SUB_KEY_FILE = os.path.join(PKI_DIR, "sub_ca_key.pem")
SUB_CERT_FILE = os.path.join(PKI_DIR, "sub_ca_cert.pem")

def ensure_pki_dir_exists():
    """Asegura que el directorio PKI existe antes de escribir nada."""
    if not os.path.exists(PKI_DIR):
        os.makedirs(PKI_DIR)
        print(f"DEBUG: Directorio {PKI_DIR} creado.")

def generate_private_key():
    """Genera una clave privada RSA de 2048 bits."""
    print("DEBUG [PKI]: Generando par de claves RSA. Longitud: 2048 bits (Estándar NIST actual).")
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    """Guarda una clave privada en disco. Crea el directorio si no existe."""
    directory = os.path.dirname(filename)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption() 
        ))

def load_key(filename):
    """Carga una clave privada desde disco."""
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_cert(cert, filename):
    """Guarda un certificado X.509 en disco."""
    directory = os.path.dirname(filename)
    if not os.path.exists(directory):
        os.makedirs(directory)

    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_cert(filename):
    """Carga un certificado X.509 desde disco."""
    with open(filename, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def setup_pki():
    """
    Inicializa la infraestructura de clave pública (PKI).
    """
    ensure_pki_dir_exists() 

    if os.path.exists(ROOT_CERT_FILE) and os.path.exists(SUB_CERT_FILE):
        return

    # 1. Crear Root CA
    print("INFO: Creando Autoridad de Certificación Raíz...")
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

    save_key(root_key, ROOT_KEY_FILE)
    save_cert(root_cert, ROOT_CERT_FILE)

    # 2. Crear Sub CA (Authority)
    print("INFO: Creando Autoridad de Certificación Subordinada...")
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

    save_key(sub_key, SUB_KEY_FILE)
    save_cert(sub_cert, SUB_CERT_FILE)

def issue_user_certificate(user_public_key, username, role):
    """
    Emite un certificado X.509 para un usuario, firmado por la Sub CA.
    """
    setup_pki()
    
    sub_key = load_key(SUB_KEY_FILE)
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

    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem):
    """
    Verifica criptográficamente la firma de un certificado.
    """
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        sub_cert = load_cert(SUB_CERT_FILE)
        
        # Verificar la firma de la Sub CA
        sub_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(), 
            user_cert.signature_hash_algorithm
        )
        
        # Verificar validez temporal
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
            raise Exception("Certificado fuera del periodo de validez")

        return True
    except Exception as e:
        print(f"ERROR PKI: Validación de certificado fallida: {e}")
        return False
