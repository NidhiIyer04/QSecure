import oqs

def generate_kyber_keypair():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)

    return {
        "algorithm": "Kyber512",
        "public_key_length": len(public_key),
        "ciphertext_length": len(ciphertext),
        "shared_secret_length": len(shared_secret)
    }