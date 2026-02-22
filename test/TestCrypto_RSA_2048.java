import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class TestCryptoRSA2048 {

    public static void main(String[] args) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        System.out.println("Generated RSA 2048 key pair.");
    }
}