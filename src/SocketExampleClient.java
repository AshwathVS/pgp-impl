import java.io.*;
import java.net.*;
import java.util.*;

class SocketExampleClient {

    public static void main(String [] args) throws Exception {

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server

        Socket s = new Socket(host, port);
        ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());
        ObjectInputStream dis = new ObjectInputStream(s.getInputStream());

        Message message = new Message("Client");
        dos.writeObject(message);
        Message message1 = (Message) dis.readObject();
        System.out.println(message1.getRecipientHash());
    }

//    public static void main(String [] args) throws Exception {
//
//        String host = args[0]; // hostname of server
//        int port = Integer.parseInt(args[1]); // port of server
//
//        Socket s = new Socket(host, port);
//        DataOutputStream dos = new DataOutputStream(s.getOutputStream());
//        DataInputStream dis = new DataInputStream(s.getInputStream());
//
//        Scanner sc = new Scanner(System.in);
//        String aLine = null;
//
//        while ((aLine = sc.nextLine()) != null) {
//            dos.writeUTF(aLine);
//            System.out.println(dis.readUTF());
//
//        }
//    }
}
