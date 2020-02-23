//package src;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class Client {

    public static Message.RequestEnvelope getReadRequestObject(String userId) {
        return new Message.RequestEnvelope<String>(CommonUtils.convertByteArrayToHexArray(CommonUtils.getSHA256HashedValue(userId)), Message.RequestEnvelope.EnumRequestType.READ);
    }

    public static byte[] serializeObject(Serializable object) throws Exception {
        System.out.println("Serialization started at: " + new Date());
        ByteArrayOutputStream baos = null;
        ObjectOutputStream oos = null;
        byte[] res = null;

        try {
            baos = new ByteArrayOutputStream();
            oos = new ObjectOutputStream(baos);

            oos.writeObject(object);
            oos.flush();

            res = baos.toByteArray();

        } catch (Exception ex) {
            throw ex;
        } finally {
            try {
                if(oos != null)
                    oos.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("Serialization ended at: " + new Date());
        return res;
    }

    public static Serializable deserializeObject(byte[] rowObject) throws Exception {
        System.out.println("Deserialization started at: " + new Date());
        ObjectInputStream ois = null;
        Serializable res = null;

        try {

            ois = new ObjectInputStream(new ByteArrayInputStream(rowObject));
            res = (Serializable) ois.readObject();

        } catch (Exception ex) {
            throw ex;
        } finally {
            try {
                if(ois != null)
                    ois.close();
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        System.out.println("Deserialization ended at: " + new Date());
        return res;

    }

    public static void printMessages(Message.ResponseEnvelope<List<Message>> responseEnvelope, String userId) {
        List<Message> messages = responseEnvelope.getResponseObject();
        if (null != messages && messages.size() > 0) {
            for (Message message : messages) {
                Message.DecryptedMessage decryptedMessage = CommonUtils.getDecryptedMessageObject(message, userId);
                if (null != decryptedMessage) {
                    decryptedMessage.printMessage();
                    System.out.println();
                }
            }
        } else {
            System.out.println("You do not have any messages. Come back after some time.");
        }
    }

    public static void main(String [] args) {

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        final String userId = args[2];

        Scanner scanner = new Scanner(System.in);
        String userInput = null;

        try {
            Socket s = new Socket(host, port);
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());
            dos.writeObject(getReadRequestObject(userId));

            Message.ResponseEnvelope<List<Message>> responseEnvelope = (Message.ResponseEnvelope<List<Message>>) dis.readObject();
            printMessages(responseEnvelope, userId);

            System.out.println("Do you want to send message? (Y/N) ");
            while (!"N".equals(userInput = scanner.nextLine().toUpperCase())) {
                if ("Y".equals(userInput.toUpperCase())) {

                    System.out.println("Who to?");
                    String recipientUserId = scanner.nextLine();

                    System.out.println("Enter your message");
                    String userMessage = scanner.nextLine();

                    // generate the message object and send request to server
                    System.out.println("Generating message object..");
                    Message message = CommonUtils.generateMessageObject(userMessage, recipientUserId, userId);
                    System.out.println("Trying to send message to server");
                    dos.writeObject(new Message.RequestEnvelope<>(message, Message.RequestEnvelope.EnumRequestType.WRITE));
                    System.out.println("Message sent to server");
                    Message.ResponseEnvelope<String> response = (Message.ResponseEnvelope<String>) dis.readObject();
                    System.out.println("Response received from server");
                    if (!response.getResponseStatus().equals(Message.ResponseEnvelope.EnumResponseStatus.OK)) {
                        System.out.println("Message not delivered.");
                    } else {
                        System.out.println("Message sent.");
                    }

                } else {
                    System.out.println("Incorrect input, try again.");
                }
                System.out.println("Do you want to send message? (Y/N) ");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    public static class AESUtil {

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

    }

    public static class RSAUtil {

        private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";

        public static void generateKeyPair(String userId) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();

                ObjectOutputStream objOut = new ObjectOutputStream(new FileOutputStream(userId + ".pub"));
                objOut.writeObject(kp.getPublic());
                objOut.close();

                objOut = new ObjectOutputStream(new FileOutputStream(userId + ".prv"));
                objOut.writeObject(kp.getPrivate());
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            } catch (IOException ioEx) {
                ioEx.printStackTrace();
            }
        }

        public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }

        public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        }

    }

    public static class CommonUtils {

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
                SecretKey aesKey = AESUtil.generateAESKey();

                //generate IV vector
                IvParameterSpec ivParameterSpec = AESUtil.getRandomIV(16);
                message.setEncryptedMsg(AESUtil.encrypt(concatenatedString.getBytes("UTF-8"), aesKey, ivParameterSpec));
                message.setIv(ivParameterSpec.getIV());

                // encrypt the aesKey with recipients public key
                PublicKey publicKey = CommonUtils.readPublicKey(recipientUserId);
                message.setKey(RSAUtil.encrypt(aesKey.getEncoded(), publicKey));

                // signature
                message.setSignature(signObject(message.generateDataToBeSigned().getBytes(), CommonUtils.readPrivateKey(senderUserId)));

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

}
