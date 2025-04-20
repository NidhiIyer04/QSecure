import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.Mac;

public class TestCrypto {

    public static void main(String[] args) {
        try {
            // AES Encryption Example
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal("Hello, World!".getBytes());
            System.out.println("Encrypted data: " + new String(encryptedData));

            // RSA KeyPair Example
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            PublicKey publicKey = keyPairGenerator.genKeyPair().getPublic();
            PrivateKey privateKey = keyPairGenerator.genKeyPair().getPrivate();
            System.out.println("Public Key: " + publicKey);
            System.out.println("Private Key: " + privateKey);

            // MessageDigest (Hashing) Example
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest("Hello, World!".getBytes());
            System.out.println("SHA-256 hash: " + new String(hash));

            // HMAC Example
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] hmacData = mac.doFinal("Hello, World!".getBytes());
            System.out.println("HMAC: " + new String(hmacData));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
