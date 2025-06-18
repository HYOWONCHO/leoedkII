from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12

def sha256_compute(messages):
    hasher = Hash(SHA256())
    hasher.update(messages)
    digest = hasher.finalize()

    return digest


def load_ec_private_key_from_pem(file_path):
    try:
        with open(file_path, 'rb') as pem_file:
            pem_data = pem_file.read()
            private_key = serialization.load_pem_private_key(
                    pem_data,
                    password=None,
                    backend=default_backend()
                )
            return private_key
    except Exception as e:
        print("Error:", e)
        return None


def read_pem_file(file_path):
    try:
        with open(file_path, 'rb') as pem_file:
            pem_data = pem_file.read()
        p_cert = x509.load_pem_x509_certificate(pem_data)
        return p_cert
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None



def get_CN(crt_subject: x509.Name) -> str:
    return next(attr.value for attr in crt_subject if attr.oid == x509.NameOID.COMMON_NAME)


def pkcs12_pbes1(password: str, pkey, clcert, cacerts: list[x509.Certificate]) -> bytes:
    encryption_algorithm = (
        PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(30)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA256())
        .build(password.encode("latin-1"))
        )

    return pkcs12.serialize_key_and_certificates(
        name=get_CN(clcert.subject).encode("latin-1"),
        key=pkey,
        cert=clcert,
        cas=cacerts,
        encryption_algorithm=encryption_algorithm,
    )

def compute_ec_dsa(privkey, digest):
    signature = privkey.sign (
        digest,
        ec.ECDSA(utils.Prehashed(SHA256())) # Indicate that the input is already a SHA256 hash
    )

    #print(f"Signature generated: {signature.hex()}")
    return signature
