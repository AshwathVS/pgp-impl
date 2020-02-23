//package src;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Server {

    private static final ConcurrentHashMap<String, List<Message>> messageStore = new ConcurrentHashMap<>(100);

    public static void insert(Message message) {
        if (messageStore.containsKey(message.getRecipientHash())) {
            messageStore.get(message.getRecipientHash()).add(message);
        } else {
            messageStore.put(message.getRecipientHash(), new LinkedList<>() {{
                add(message);
            }});
        }
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

    public static void main(String[] args) throws Exception {

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
                        insert(message);
                        System.out.println("Message stored.");
                        dos.writeObject(new Message.ResponseEnvelope<String>("Ok", Message.ResponseEnvelope.EnumResponseStatus.OK));
                    } else {
                        System.out.println("Unknown operation, rejecting request.");
                    }
                }
            } catch (IOException e) {
//                System.err.println("Client closed its connection.");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            s.close();
        }
    }
}
