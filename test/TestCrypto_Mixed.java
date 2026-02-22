import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;

public class TestCryptoMixed {

    public static void main(String[] args) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest("test".getBytes());

        System.out.println("Multiple crypto operations executed.");
    }
}