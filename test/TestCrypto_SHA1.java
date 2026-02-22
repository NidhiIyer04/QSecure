import java.security.MessageDigest;

public class TestCryptoSHA1 {

    public static void main(String[] args) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest("hello".getBytes());

        System.out.println("SHA-1 hash generated.");
    }
}