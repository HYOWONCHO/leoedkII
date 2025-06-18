from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12

import os

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
    der_signature = privkey.sign (
            digest,
            ec.ECDSA(utils.Prehashed(SHA256())) # Indicate that the input is already a SHA256 hash
    )

    print(f"DER-encoded signature length: {len(der_signature)} bytes")
    print(f"DER-encoded signature (hex): {der_signature.hex()}")

    r, s = utils.decode_dss_signature(der_signature)

    print(f"\nExtracted r (integer): {r}")
    print(f"Extracted s (integer): {s}")

    # SECP256R1의 order (NIST P-256)
    curve_order_n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        # Encode r and s to 32-byte big-endian
#   r_bytes = utils.encode_known_scalar(r, curve_order_n)
#   s_bytes = utils.encode_known_scalar(s, curve_order_n)
    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')


    raw_signature_64_byte = r_bytes + s_bytes

    print(f"\nRaw r (32-byte hex): {r_bytes.hex()}")
    print(f"Raw s (32-byte hex): {s_bytes.hex()}")
    print(f"Concatenated 64-byte raw signature (hex): {raw_signature_64_byte.hex()}")
    print(f"Length of 64-byte raw signature: {len(raw_signature_64_byte)} bytes")
    return raw_signature_64_byte


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
    # 1. Generate an ECDSA private key for the secp256r1 curve
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # 2. Access the curve object associated with the private key
    curve_associated_with_key = private_key.curve

    # 3. Now you can access the 'order' attribute from that curve object
    # SECP256R1의 order (NIST P-256)
    curve_order_n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


    print(f"The order (n) of the {private_key.curve.name} curve is: {curve_order_n}")

    # You would then use this `curve_order_n` in functions like `utils.encode_known_scalar`
    # as shown in the previous example.

    # Full example (revisiting the raw signature part with the fix):
    message = b"Data for fixed-size signature."
    hasher = Hash(SHA256())
    hasher.update(message)
    digest = hasher.finalize()

    der_signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(SHA256()))
    )

    r, s = utils.decode_dss_signature(der_signature)

    # Correctly getting the curve order from the private_key.curve object
    curve_order_n_for_encoding = private_key.curve.order

    r_bytes = utils.encode_known_scalar(r, curve_order_n_for_encoding)
    s_bytes = utils.encode_known_scalar(s, curve_order_n_for_encoding)

    raw_signature_64_byte = r_bytes + s_bytes

    print(f"\nConcatenated 64-byte raw signature (hex): {raw_signature_64_byte.hex()}")
    print(f"Length of 64-byte raw signature: {len(raw_signature_64_byte)} bytes")

#   # 1. Generate a private key
#   private_key = ec.generate_private_key(ec.SECP256R1())
#
#   # 2. Define your message and compute its hash
#   message = b"This message will be signed."
#   hasher = Hash(SHA256())
#   hasher.update(message)
#   digest = hasher.finalize()
#
#   # 3. Get the signature (which will be DER-encoded by default)
#   der_signature = private_key.sign(
#       digest,
#       ec.ECDSA(utils.Prehashed(SHA256()))
#   )
#
#   print(f"DER-encoded signature length: {len(der_signature)} bytes")
#   print(f"DER-encoded signature (hex): {der_signature.hex()}")
#
#   # 4. Extract r and s from the DER signature
#   r, s = utils.decode_dss_signature(der_signature)
#
#   print(f"\nExtracted r (integer): {r}")
#   print(f"Extracted s (integer): {s}")
#
#   # 5. Convert r and s to fixed-size (e.g., 32-byte for secp256r1) big-endian byte strings
#   # The order of the curve (n) determines the maximum size of r and s.
#   # For secp256r1, the order is a 256-bit number, so 32 bytes.
#   # `utils.encode_known_scalar` will zero-pad to the correct length.
#   # The curve order `n` is required for this.
#   curve_order_n = private_key.curve.order
#
#   # Encode r and s to 32-byte big-endian
#   r_bytes = utils.encode_known_scalar(r, curve_order_n)
#   s_bytes = utils.encode_known_scalar(s, curve_order_n)
#
#   # Concatenate them to get the 64-byte raw signature
#   raw_signature_64_byte = r_bytes + s_bytes
#
#   print(f"\nRaw r (32-byte hex): {r_bytes.hex()}")
#   print(f"Raw s (32-byte hex): {s_bytes.hex()}")
#   print(f"Concatenated 64-byte raw signature (hex): {raw_signature_64_byte.hex()}")
#   print(f"Length of 64-byte raw signature: {len(raw_signature_64_byte)} bytes")
#
    # --- Verification using the raw 64-byte signature ---
    # For verification, you would typically convert the raw 64-byte signature back to r and s
    # and then use them with the public key.
    # public_key = private_key.public_key() # Get public key

    # r_from_raw = int.from_bytes(raw_signature_64_byte[:32], 'big')
    # s_from_raw = int.from_bytes(raw_signature_64_byte[32:], 'big')

    # try:
    #     # Note: You can't directly verify a 64-byte raw signature with public_key.verify()
    #     # as it expects DER or `signature.from_encoded_dss_signature` takes an r,s pair directly
    #     # You'd typically re-encode to DER or use `verify_dss_signature` (if available for that curve)
    #     # A common approach is to recreate the DER for verification or use `utils.encode_dss_signature` for verification with other systems
    #     recreated_der_signature = utils.encode_dss_signature(r_from_raw, s_from_raw)
    #     public_key.verify(
    #         recreated_der_signature,
    #         digest,
    #         ec.ECDSA(utils.Prehashed(SHA256()))
    #     )
    #     print("\nVerification successful with recreated DER signature.")
    # except InvalidSignature:
    #     print("\nVerification failed with recreated DER signature.")




#   # 1. Generate Key Pair
#
#   print("ECDSA testing start !!!! ")
#   private_key = ec.generate_private_key(ec.SECP256R1())
#   public_key = private_key.public_key()
#
#   # 2. Prepare Message (and its hash/digest)
#   message = b"My secret data to sign."
#   hasher = Hash(SHA256())
#   hasher.update(message)
#   digest = hasher.finalize()
#
#   print(f"Digest : {digest.hex()}")
#
#   # 3. Sign the Digest
#   signature = private_key.sign(
#       digest,
#       ec.ECDSA(utils.Prehashed(SHA256()))
#   )
#
#   print(f"Signature Len : {len(signature)}")
#   print(f"Signature Hex : {signature.hex()}")
#
#   # 4. Verify the Signature
#   try:
#       public_key.verify(
#           signature,
#           digest, # Use the same digest that was signed
#           ec.ECDSA(utils.Prehashed(SHA256()))
#       )
#       print("Signature is VALID.")
#   except InvalidSignature:
#       print("Signature is INVALID.")
#
#   # 1. Generate a private key (or load an existing one)
#   private_key = ec.generate_private_key(ec.SECP256R1())
#
#   # 2. Define your message
#   original_message = b"This is the important data for which I need a signature."
#
#   # 3. Compute the hash (digest) of the message
#   # This hash is the *input* to the signing function.
#   hasher = Hash(SHA256())
#   hasher.update(original_message)
#   message_digest = hasher.finalize() # This is the hash value
#
#   print(f"Original Message: {original_message.decode()}")
#   print(f"Computed Message Hash (Digest): {message_digest.hex()}")
#
#   # 4. Compute the digital signature using the private key and the message digest
#   # The variable 'digital_signature_value' will hold the result of private_key.sign()
#   digital_signature_value = private_key.sign(
#       message_digest,                      # Input: The hash (digest) you computed
#       ec.ECDSA(utils.Prehashed(SHA256()))  # Specifies the signing algorithm and that input is pre-hashed
#   )
#
#   # 5. You now have the digital signature value
#   print(f"\nObtained Digital Signature Value (bytes): {digital_signature_value}")
#   print(f"Obtained Digital Signature Value (hex): {digital_signature_value.hex()}")
#   print(f"Length of the Signature: {len(digital_signature_value)} bytes")
#
