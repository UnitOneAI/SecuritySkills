import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

class VulnerablePasswordHasher {
    static byte[] hashPassword(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(password.getBytes(StandardCharsets.UTF_8));
    }
}
