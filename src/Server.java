//package src;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Server {

    public static void insert(Message message, Map<String, List<Message>> messageMap) {
        if (messageMap.containsKey(message.getRecipientHash())) {
            messageMap.get(message.getRecipientHash()).add(message);
        } else {
            messageMap.put(message.getRecipientHash(), new ArrayList<>(10) {{
                add(message);
            }});
        }
    }

    public static void main(String[] args) throws Exception {

        Map<String, List<Message>> messageStore = new HashMap<>(100);

        int port = Integer.parseInt(args[0]);
        ServerSocket ss = new ServerSocket(port);

        System.out.println("Waiting incoming connection...");

        while(true) {

            Socket s = ss.accept();
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());

            Object inp = null;

            try {
                while ((inp = dis.readObject()) != null) {
                    RequestEnvelope<Object> messageRequestEnvelope = (RequestEnvelope<Object>) inp;
                    RequestEnvelope.EnumRequestType enumRequestType = messageRequestEnvelope.getMessageType();

                    // Reading the messages
                    if (enumRequestType == RequestEnvelope.EnumRequestType.READ) {
                        String userId = (String) messageRequestEnvelope.getMessageObject();
                        List<Message> messages = messageStore.get(userId);

                        // deleting the messages
                        messageStore.put(userId, null);

                        // send the messages in a response envelope
                        ResponseEnvelope<List<Message>> responseEnvelope = new ResponseEnvelope<>(messages, ResponseEnvelope.EnumResponseStatus.OK);
                        dos.writeObject(responseEnvelope);
                    }

                    // writing (storing) a new message
                    else if (enumRequestType == RequestEnvelope.EnumRequestType.WRITE) {
                        Message message = (Message) messageRequestEnvelope.getMessageObject();
                        insert(message, messageStore);
                    } else {
                        System.out.println("Unknown operation, rejecting request.");
                    }
                }
            } catch (IOException e) {
                System.err.println("Client closed its connection.");
            }

        }
    }
}
