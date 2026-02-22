import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class TestCryptoRSA1024 {

    public static void main(String[] args) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();

        System.out.println("Generated weak RSA 1024 key pair.");
    }
}