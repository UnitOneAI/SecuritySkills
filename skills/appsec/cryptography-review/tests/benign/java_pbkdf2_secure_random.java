import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class SecurePbkdf2PasswordHasher {
    private static final SecureRandom RNG = new SecureRandom();

    static byte[] newSalt() {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        return salt;
    }

    static byte[] hashPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 310_000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
