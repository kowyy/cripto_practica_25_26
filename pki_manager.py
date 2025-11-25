import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Archivos para persistencia de la PKI
PKI_DIR = "pki_store"
ROOT_KEY_FILE = os.path.join(PKI_DIR, "root_ca_key.pem")
ROOT_CERT_FILE = os.path.join(PKI_DIR, "root_ca_cert.pem")
SUB_KEY_FILE = os.path.join(PKI_DIR, "sub_ca_key.pem")
SUB_CERT_FILE = os.path.join(PKI_DIR, "sub_ca_cert.pem")

if not os.path.exists(PKI_DIR):
    os.makedirs(PKI_DIR)

def generate_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption() # En producción, esto debería ir cifrado
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

def setup_pki():
    """Inicializa la PKI: Crea Root CA y Sub CA si no existen."""
    if os.path.exists(ROOT_CERT_FILE) and os.path.exists(SUB_CERT_FILE):
        print("INFO: PKI ya inicializada. Cargando CAs...")
        return

    print("INFO: Inicializando PKI (Root CA + Sub CA)...")

    # 1. Generar Root CA 
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
        # Validez de 10 años
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256())

    save_key(root_key, ROOT_KEY_FILE)
    save_cert(root_cert, ROOT_CERT_FILE)

    # 2. Generar Sub CA (Firmada por Root)
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
    ).sign(root_key, hashes.SHA256()) # Firmado con la clave de la Root CA

    save_key(sub_key, SUB_KEY_FILE)
    save_cert(sub_cert, SUB_CERT_FILE)
    print("INFO: PKI inicializada correctamente.")

def issue_user_certificate(user_public_key, username, role):
    """Emite un certificado para un usuario firmado por la Sub CA."""
    setup_pki() # Asegurar que la PKI existe
    
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
    ).sign(sub_key, hashes.SHA256()) # Firmado por la Sub CA

    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem):
    """
    Verifica la validez de un certificado de usuario comprobando:
    1. Firma válida de la Sub CA.
    2. Fechas de validez.
    (En un sistema real también se validaría la cadena completa hasta Root CA).
    """
    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem)
        sub_cert = load_cert(SUB_CERT_FILE)
        
        # Verificar firma usando la clave pública de la Sub CA
        sub_cert.public_key().verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            import_padding_asymmetric(user_cert.signature_algorithm_oid), # Helper implícito o padding standard
            user_cert.signature_hash_algorithm
        )
        
        # Verificar fechas
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc):
            raise Exception("Certificado expirado o aún no válido.")

        return True
    except Exception as e:
        print(f"ERROR PKI: Validación de certificado fallida: {e}")
        return False

# Helper para padding en verificación de certs (simplificado)
from cryptography.hazmat.primitives.asymmetric import padding
def import_padding_asymmetric(oid):
    return padding.PKCS1v15() # X.509 suele usar PKCS1v15 para firmas de certs
