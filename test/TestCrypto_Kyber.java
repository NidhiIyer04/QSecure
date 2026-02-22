import org.openquantumsafe.KeyEncapsulation;

public class TestCryptoKyber {

    public static void main(String[] args) throws Exception {

        KeyEncapsulation kem = new KeyEncapsulation("Kyber512");
        byte[] publicKey = kem.generateKeyPair().getPublic();

        System.out.println("Generated Kyber key pair.");
    }
}