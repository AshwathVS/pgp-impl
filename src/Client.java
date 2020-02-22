//package src;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    public static void main(String [] args) throws Exception {

        String host = args[0]; // hostname of server
        int port = Integer.parseInt(args[1]); // port of server
        String userId = args[2];

        Socket s = new Socket(host, port);
        DataOutputStream dos = new DataOutputStream(s.getOutputStream());
        DataInputStream dis = new DataInputStream(s.getInputStream());

        Scanner sc = new Scanner(System.in);
        String aLine = null;

        while ((aLine = sc.nextLine()) != null) {

            dos.writeUTF(aLine);
            System.out.println(dis.readUTF());

        }
    }
}
