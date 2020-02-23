//package src;

import java.io.*;
import java.net.*;

class SocketExampleServer {

    public static void main(String [] args) throws Exception {

        int port = Integer.parseInt(args[0]);

        ServerSocket ss = new ServerSocket(port);
        System.out.println("Waiting incoming connection...");

        while(true) {
            Socket s = ss.accept();
            ObjectInputStream dis = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream dos = new ObjectOutputStream(s.getOutputStream());

            Message x = null;

            try {
                while ((x = (Message) dis.readObject()) != null) {

                    System.out.println(x.getRecipientHash());
                    dos.writeObject(new Message("Server"));

                }
            }
            catch(IOException e) {
                System.err.println("Client closed its connection.");
            }
        }
    }
}

