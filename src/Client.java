//package src;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.List;
import java.util.Scanner;

public class Client {

    public static RequestEnvelope getReadRequestObject(String userId) {
        return new RequestEnvelope<String>(CommonUtils.convertByteArrayToHexArray(CommonUtils.getSHA256HashedValue(userId)), RequestEnvelope.EnumRequestType.READ);
    }

    public static void main(String [] args) throws Exception {

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        final String userId = args[2];

        Socket s = new Socket(host, port);
        ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
        ObjectInputStream dis = new ObjectInputStream(s.getInputStream());

        Scanner scanner = new Scanner(System.in);
        String userInput = null;

        boolean readMessage = true;
        do {
            if (readMessage) {
                readMessage = false;
                dos.writeObject(getReadRequestObject(userId));

                ResponseEnvelope<List<Message>> responseEnvelope = (ResponseEnvelope<List<Message>>) dis.readObject();
                List<Message> messages = responseEnvelope.getResponseObject();
                if (null != messages && messages.size() > 0) {
                    for (Message message : messages) {
                        DecryptedMessage decryptedMessage = CommonUtils.getDecryptedMessageObject(message, userId);
                        if (null != decryptedMessage) {
                            decryptedMessage.printMessage();
                            System.out.println();
                        }
                    }
                } else {
                    System.out.println("You do not have any messages. Come back after some time.");
                }
                System.out.println("Do you want to send message? (Y/N) ");
                continue;
            }

            if ("Y".equals(userInput.toUpperCase())) {
                System.out.println("Who to?");
//                String recipientUserId = scanner.nextLine();
                String recipientUserId = "jay";

                System.out.println("Enter your message");
//                String userMessage = scanner.nextLine();
                String userMessage = "this is ashwath";

                // generate the message object and send request to server
                Message message = CommonUtils.generateMessageObject(userMessage, recipientUserId, userId);
                dos.writeObject(new RequestEnvelope<>(message, RequestEnvelope.EnumRequestType.WRITE));

            } else {
                System.out.println("Incorrect input, try again.");
            }
        } while (!"N".equals(userInput = scanner.nextLine().toUpperCase()));

    }
}
