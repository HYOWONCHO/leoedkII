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

def compute_ec_dsa_sign(privkey, digest):
    signature = privkey.sign (
        digest,
        ec.ECDSA(utils.Prehashed(SHA256())) # Indicate that the input is already a SHA256 hash
    )

    #return sha256_compute(signature)
    #print(f"Signature generated: {signature.hex()}")
    return signature


def compute_ec_dsa_verify(pubkey, signature, digest):
    try:
        pubkey.verify (
            signature,
            digest,
            ec.ECDSA(utils.Prehashed(SHA256())) # Indicate that the input is already a SHA256 hash
        )

        print("Signature is VALID")
    except InvalidSignature:
        print("Signature is INVALID")
        


def ecdsa_sign_verify_test():
    # 1. Generate Key Pair

    print("ECDSA testing start !!!! ")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # 2. Prepare Message (and its hash/digest)
    message = b"My secret data to sign."
    hasher = Hash(SHA256())
    hasher.update(message)
    digest = hasher.finalize()

    print(f"Digest : {digest.hex()}")

    # 3. Sign the Digest
    signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(SHA256()))
    )

    print(f"Signature Len : {len(signature)}")
    print(f"Signature Hex : {signature.hex()}")

    # 4. Verify the Signature
    try:
        public_key.verify(
            signature,
            digest, # Use the same digest that was signed
            ec.ECDSA(utils.Prehashed(SHA256()))
        )
        print("Signature is VALID.")
    except InvalidSignature:
        print("Signature is INVALID.")

    # 1. Generate a private key (or load an existing one)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 2. Define your message
    original_message = b"This is the important data for which I need a signature."

    # 3. Compute the hash (digest) of the message
    # This hash is the *input* to the signing function.
    hasher = Hash(SHA256())
    hasher.update(original_message)
    message_digest = hasher.finalize() # This is the hash value

    print(f"Original Message: {original_message.decode()}")
    print(f"Computed Message Hash (Digest): {message_digest.hex()}")

    # 4. Compute the digital signature using the private key and the message digest
    # The variable 'digital_signature_value' will hold the result of private_key.sign()
    digital_signature_value = private_key.sign(
        message_digest,                      # Input: The hash (digest) you computed
        ec.ECDSA(utils.Prehashed(SHA256()))  # Specifies the signing algorithm and that input is pre-hashed
    )

    # 5. You now have the digital signature value
    print(f"\nObtained Digital Signature Value (bytes): {digital_signature_value}")
    print(f"Obtained Digital Signature Value (hex): {digital_signature_value.hex()}")
    print(f"Length of the Signature: {len(digital_signature_value)} bytes")

