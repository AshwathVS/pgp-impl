package src;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

public class CommonUtils {

    public static byte[] getSHA256HashedValue(String input) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return messageDigest.digest(input.getBytes());
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
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
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] signObject(byte[] message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    public static boolean verifySign(byte[] message, PublicKey publicKey, byte[] signedSignature) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(signedSignature);
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

            String concatenatedString = senderUserId + "\n" + unencryptedMessage;

            // generate the aes key
            System.out.println("Generating aes key" + new Date());
            SecretKey aesKey = AESUtil.generateAESKey();

            //generate IV vector
            System.out.println("Generating IV vector: " + new Date());
            IvParameterSpec ivParameterSpec = AESUtil.getRandomIV(16);
            message.setEncryptedMsg(AESUtil.encrypt(concatenatedString.getBytes("UTF-8"), aesKey, ivParameterSpec));
            message.setIv(ivParameterSpec.getIV());

            // encrypt the aesKey with recipients public key
            System.out.println("Signing the aes key" + new Date());
            PublicKey publicKey = CommonUtils.readPublicKey(recipientUserId);
            message.setKey(RSAUtil.encrypt(aesKey.getEncoded(), publicKey));

            // signature
            System.out.println("Signing the message object" + new Date());
            message.setSignature(signObject(message.generateDataToBeSigned().getBytes(), CommonUtils.readPrivateKey(senderUserId)));
            System.out.println("Message object generated..." + new Date());

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return message;
    }


    public static Message.DecryptedMessage getDecryptedMessageObject(Message encryptedMessage, String loggedInUserId) {
        Message.DecryptedMessage decryptedMessage = null;
        try {
            // get aes key using current user private key
            byte[] aesKey = RSAUtil.decrypt(encryptedMessage.getKey(), CommonUtils.readPrivateKey(loggedInUserId));

            // using the aes key, iv get the encrypted message
            SecretKey secretKey = new SecretKeySpec(aesKey, 0, aesKey.length, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptedMessage.getIv());
            String plainMessage = new String(AESUtil.decrypt(encryptedMessage.getEncryptedMsg(), secretKey, ivParameterSpec));
            String[] splitMessage = plainMessage.split("\n");

            decryptedMessage = new Message.DecryptedMessage();

            decryptedMessage.setMessage(splitMessage[1]);
            decryptedMessage.setSenderUserId(splitMessage[0]);
            decryptedMessage.setDateSent(encryptedMessage.getTimestamp());

            //verify the signature
            boolean isSignVerified = verifySign(encryptedMessage.generateDataToBeSigned().getBytes(), CommonUtils.readPublicKey(loggedInUserId), encryptedMessage.getSignature());
            decryptedMessage.setSignatureVerified(isSignVerified);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return decryptedMessage;
    }

}
