package src;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Date;

public class AESUtil {
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec getRandomIV(int size) {
        IvParameterSpec ivParameterSpec = null;
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);

            // Parameter Spec
            ivParameterSpec = new IvParameterSpec(iv);
        } catch (NoSuchAlgorithmException ex) {

        }
        return ivParameterSpec;
    }

    public static byte[] encrypt(byte[] input, SecretKey key, IvParameterSpec ivParameterSpec) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(input);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static byte[] decrypt(byte[] encryptedBytes, SecretKey key, IvParameterSpec ivParameterSpec) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            return cipher.doFinal(encryptedBytes);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }


    /**
     * Each message is encrypted as follows. The client generates a fresh 256-bit AES
     * key. It then generates 16 random bytes to be used as the IV. The sender userid is
     * concatenated with the user's message, separated by the newline character, and is then encrypted
     * using AES/CBC/PKCS5Padding with the above AES key and IV. The AES key is then
     * encrypted using RSA/ECB/PKCS1Padding with the public key of the recipient. Finally, the
     * encrypted AES key, the (unencrypted) IV, and the encrypted message are stored in the
     * key, iv and encrytedMsg members of a Message object.
     *
     * @param unencryptedMessage
     * @param recipientUserId
     */
    public static Message generateMessageObject(String unencryptedMessage, String recipientUserId) {
        Message message = null;
//        private String recipientHash; // SHA-256 hash of recipient userid
//        private Date timestamp;       // timestamp (java.util.Date)
//        private byte[] key;           // AES key used, encrypted with RSA
//        private byte[] iv;            // unencrypted IV
//        private byte[] encryptedMsg;  // sender userid + message, encrypted with AES
//        private byte[] signature;     // signature of all above
        try {
            message = new Message();
            message.setTimestamp(new Date());

            // generate hash of user id and storing in recipientHash
            message.setRecipientHash(CommonUtils.convertByteArrayToHexArray(CommonUtils.getSHA256HashedValue(recipientUserId)));

            String concatenatedString = recipientUserId + "\n" + unencryptedMessage;

            // generate the aes key
            SecretKey aesKey = generateAESKey();

            //generate IV vector
            IvParameterSpec ivParameterSpec = getRandomIV(16);
            message.setEncryptedMsg(encrypt(concatenatedString.getBytes("UTF-8"), aesKey, ivParameterSpec));
            message.setIv(ivParameterSpec.getIV());

            // encrypt the aesKey with recipients public key
            PublicKey publicKey = CommonUtils.readPublicKey(recipientUserId);
            message.setKey(RSAUtil.encrypt(aesKey.getEncoded(), publicKey));

            // signature


        } catch (Exception ex) {

        }
        return message;
    }
}
