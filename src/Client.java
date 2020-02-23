
import javax.crypto.BadPaddingException;
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
import java.util.Random;
import java.util.Scanner;

public class Client {

    public static Message.RequestEnvelope getReadRequestObject(String userId) {
        return new Message.RequestEnvelope<String>(CommonUtils.convertByteArrayToHexArray(CommonUtils.getSHA256HashedValue(userId)), Message.RequestEnvelope.EnumRequestType.READ);
    }

    public static void printMessages(Message.ResponseEnvelope<List<Message>> responseEnvelope, String userId) {
        List<Message> messages = responseEnvelope.getResponseObject();
        if (null != messages && messages.size() > 0) {
            System.out.println("You have received " + messages.size() + " messages.");
            for (Message message : messages) {
                try {
                    Message.DecryptedMessage decryptedMessage = CommonUtils.getDecryptedMessageObject(message, userId);
                    if (null != decryptedMessage) {
                        decryptedMessage.printMessage();
                        System.out.println();
                    }
                } catch (BadPaddingException ex) {
                    System.out.println("Unable to decrypt message, please check the keys.");
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

            // initialising sockets and streams for data transfer
            Socket s = new Socket(host, port);
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());
            dos.writeObject(getReadRequestObject(userId));

            Message.ResponseEnvelope<List<Message>> responseEnvelope = (Message.ResponseEnvelope<List<Message>>) dis.readObject();
            printMessages(responseEnvelope, userId);

            System.out.println("Do you want to send message? (Y/N) ");
            while (!"N".equals(userInput = scanner.nextLine().toUpperCase())) {
                if ("Y".equals(userInput.toUpperCase())) {

                    // gather message info
                    System.out.println("Who to?");
                    String recipientUserId = scanner.nextLine();

                    System.out.println("Enter your message");
                    String userMessage = scanner.nextLine();

                    // generate the message object and send request to server
                    Message message = CommonUtils.generateMessageObject(userMessage, recipientUserId, userId);

                    // send the object to server
                    dos.writeObject(new Message.RequestEnvelope<>(message, Message.RequestEnvelope.EnumRequestType.WRITE));

                    // read response from server
                    Message.ResponseEnvelope<String> response = (Message.ResponseEnvelope<String>) dis.readObject();

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

    /**
     * This class is a class which will process the encryption and decryption using the AES style
     *
     */
    public static class AESUtil {

        private static final String AES_ALGORITH = "AES/CBC/PKCS5Padding";

        public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        }

        /**
         * Used SecureRandom to generate the byte array, but is very slow.
         * Using random instead of SecureRandom for smooth running of the client and server
         */
        public static IvParameterSpec getRandomIV(int size) {
            IvParameterSpec ivParameterSpec = null;
            try {

                // SecureRandom secureRandom = SecureRandom.getInstanceStrong();
                // byte[] iv = new byte[16];
                // secureRandom.nextBytes(iv);

                byte[] iv = new byte[size];
                new Random().nextBytes(iv);

                // Parameter Spec
                ivParameterSpec = new IvParameterSpec(iv);
            } catch (Exception ex) {
                // Secure random causes exception, leaving the catch block even though we can remove it.
            }
            return ivParameterSpec;
        }

        public static byte[] encrypt(byte[] input, SecretKey key, IvParameterSpec ivParameterSpec) {
            try {
                Cipher cipher = Cipher.getInstance(AES_ALGORITH);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
                return cipher.doFinal(input);
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }

        public static byte[] decrypt(byte[] encryptedBytes, SecretKey key, IvParameterSpec ivParameterSpec) {
            try {
                Cipher cipher = Cipher.getInstance(AES_ALGORITH);
                cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
                return cipher.doFinal(encryptedBytes);
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }

    }

    /**
     * This class is responsible for the RSA functions.
     */
    public static class RSAUtil {

        private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

        public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }

        public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        }

    }

    /**
     * This class will carry all the utility functions like reading the keys, hashing, signing, generating the Message object
     * and decrypting the system.
     */

    public static class CommonUtils {

        private static final String SHA256_WITH_RSA = "SHA256withRSA";

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
            } catch (ClassNotFoundException | IOException ex) {
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
            Signature signature = Signature.getInstance(SHA256_WITH_RSA);
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        }

        public static boolean verifySign(byte[] message, PublicKey publicKey, byte[] signedSignature) throws Exception {
            Signature signature = Signature.getInstance(SHA256_WITH_RSA);
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

                //generate IV vector and store the IV in the message object
                IvParameterSpec ivParameterSpec = AESUtil.getRandomIV(16);
                message.setIv(ivParameterSpec.getIV());

                // encrypting the message with the aes key
                message.setEncryptedMsg(AESUtil.encrypt(concatenatedString.getBytes("UTF-8"), aesKey, ivParameterSpec));

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


        /**
         * This method will decrypt the messages obtained from the server
         * @param encryptedMessage
         * @param loggedInUserId
         * @return
         * @throws BadPaddingException
         */
        public static Message.DecryptedMessage getDecryptedMessageObject(Message encryptedMessage, String loggedInUserId) throws BadPaddingException {
            Message.DecryptedMessage decryptedMessage = null;
            try {
                // get aes key using current user private key
                byte[] aesKey = RSAUtil.decrypt(encryptedMessage.getKey(), CommonUtils.readPrivateKey(loggedInUserId));

                // using the aes key, iv get the encrypted message
                SecretKey secretKey = new SecretKeySpec(aesKey, 0, aesKey.length, "AES");

                // read the IV
                IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptedMessage.getIv());

                // decrypt the encrypted message with the secret key and the IV
                String plainMessage = new String(AESUtil.decrypt(encryptedMessage.getEncryptedMsg(), secretKey, ivParameterSpec));

                // split the message and store the details
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
