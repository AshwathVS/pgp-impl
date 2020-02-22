//package src;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

public class CommonUtils {
    public static byte[] getSHA256HashedValue(String input) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        return messageDigest.digest(input.getBytes());
    }

    public static String convertByteArrayToHexArray(byte[] hash) {
        return new BigInteger(1, hash).toString(16);
    }

    public static PublicKey readPublicKey(String userId) {
        PublicKey publicKey = null;
        try {
            FileInputStream fileInputStream = new FileInputStream(userId + ".pub");
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            publicKey = (PublicKey) objectInputStream.readObject();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey readPrivateKey(String userId) {
        PrivateKey privateKey = null;
        try {
            FileInputStream fileInputStream = new FileInputStream(userId + ".prv");
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            privateKey = (PrivateKey) objectInputStream.readObject();
            Object object = new Object();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] signObject(Serializable serializable, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        SignedObject signedObject = new SignedObject(serializable, privateKey, signature);
        return signedObject.getSignature();
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
    public static Message generateMessageObject(String unencryptedMessage, String recipientUserId, String senderUserId) {
        Message message = null;
        try {
            message = new Message();
            message.setTimestamp(new Date());

            // generate hash of user id and storing in recipientHash
            message.setRecipientHash(CommonUtils.convertByteArrayToHexArray(CommonUtils.getSHA256HashedValue(recipientUserId)));

            String concatenatedString = recipientUserId + "\n" + unencryptedMessage;

            // generate the aes key
            SecretKey aesKey = AESUtil.generateAESKey();

            //generate IV vector
            IvParameterSpec ivParameterSpec = AESUtil.getRandomIV(16);
            message.setEncryptedMsg(AESUtil.encrypt(concatenatedString.getBytes("UTF-8"), aesKey, ivParameterSpec));
            message.setIv(ivParameterSpec.getIV());

            // encrypt the aesKey with recipients public key
            PublicKey publicKey = CommonUtils.readPublicKey(recipientUserId);
            message.setKey(RSAUtil.encrypt(aesKey.getEncoded(), publicKey));

            // signature
            message.setSignature(signObject(message, CommonUtils.readPrivateKey(senderUserId)));

        } catch (Exception ex) {

        }
        return message;
    }


    public static DecryptedMessage getDecryptedMessageObject(Message encryptedMessage, String loggedInUserId) {
        
    }

    public static void main(String[] args) throws Exception {
        PublicKey publicKey = readPublicKey("ash");
//        System.out.println(publicKey != null);
        String base = "This is ashwath";
        byte[] encrypted = RSAUtil.encrypt(base.getBytes(), publicKey);



        PrivateKey privateKey = readPrivateKey("ash");
        String decrypted = new String(RSAUtil.decrypt(encrypted, privateKey));
        System.out.println(decrypted);
//        System.out.println(privateKey != null);


        System.out.println("AES PART....");
        SecretKey secretKey = AESUtil.generateAESKey();
        IvParameterSpec ivParameterSpec = AESUtil.getRandomIV(16);
        byte[] encrp = AESUtil.encrypt(base.getBytes(), secretKey, ivParameterSpec);
        String decryp = new String(AESUtil.decrypt(encrp, secretKey, ivParameterSpec));
        System.out.println(decryp);
    }
}
