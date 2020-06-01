package src;

import java.io.*;
import java.net.Socket;
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
                    System.out.println("Generating message object.." + new Date());
                    Message message = CommonUtils.generateMessageObject(userMessage, recipientUserId, userId);
                    System.out.println("Trying to send message to server" + new Date());
                    dos.writeObject(new Message.RequestEnvelope<>(message, Message.RequestEnvelope.EnumRequestType.WRITE));
                    System.out.println("Message sent to server" + new Date());
                    Message.ResponseEnvelope<String> response = (Message.ResponseEnvelope<String>) dis.readObject();
                    System.out.println("Response received from server" + new Date());
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

}
