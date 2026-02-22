import time
import oqs
from Crypto.PublicKey import RSA

def benchmark():

    # RSA
    start = time.time()
    RSA.generate(2048)
    rsa_time = time.time() - start

    # Kyber
    start = time.time()
    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.generate_keypair()
    kyber_time = time.time() - start

    return {
        "rsa_2048_keygen_time_sec": rsa_time,
        "kyber512_keygen_time_sec": kyber_time
    }