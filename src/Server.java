package src;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Server {

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        ConcurrentHashMap<String, List<Message>> messageStore = new ConcurrentHashMap<>(100);
        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);

        System.out.println("Waiting incoming connection...");

        while(true) {

            Socket s = ss.accept();
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());

            Object inp = null;

            try {

                while ((inp = dis.readObject()) != null) {
                    Message.RequestEnvelope<Object> messageRequestEnvelope = (Message.RequestEnvelope<Object>) inp;
                    Message.RequestEnvelope.EnumRequestType enumRequestType = messageRequestEnvelope.getMessageType();

                    // Reading the messages
                    if (enumRequestType == Message.RequestEnvelope.EnumRequestType.READ) {
                        String userId = (String) messageRequestEnvelope.getMessageObject();
                        List<Message> messages = messageStore.get(userId);

                        // deleting the messages
                        messageStore.remove(userId);

                        // send the messages in a response envelope
                        Message.ResponseEnvelope<List<Message>> responseEnvelope = new Message.ResponseEnvelope<List<Message>>(messages, Message.ResponseEnvelope.EnumResponseStatus.OK);
                        dos.writeObject(responseEnvelope);
                    }

                    // writing (storing) a new message
                    else if (enumRequestType == Message.RequestEnvelope.EnumRequestType.WRITE) {
                        Message message = (Message) messageRequestEnvelope.getMessageObject();

                        /**
                         * Store the messages
                         */
                        final String recipientHash = message.getRecipientHash();
                        if (messageStore.containsKey(recipientHash)) {
                            messageStore.get(recipientHash).add(message);
                        } else {
                            List<Message> messages = new ArrayList<>(10);
                            messages.add(message);
                            messageStore.put(recipientHash, messages);
                        }
                        System.out.println("Message stored.");

                        // send response
                        dos.writeObject(new Message.ResponseEnvelope<String>("Ok", Message.ResponseEnvelope.EnumResponseStatus.OK));
                    } else {
                        System.out.println("Unknown operation, rejecting request.");
                    }
                }
            } catch (IOException e) {
                System.err.println("Client closed its connection.");
            } catch (Exception ex) {
//                ex.printStackTrace();
            }
            s.close();
        }
    }
}
