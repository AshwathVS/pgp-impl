package src;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
