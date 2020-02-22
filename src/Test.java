import java.io.*;
import java.util.Date;

public class Test {
    public static byte[] serializeObject(Serializable object) throws Exception {
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

        return res;
    }

    public static Serializable deserializeObject(byte[] rowObject) throws Exception {
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

        return res;

    }
    public static void main(String[] args) throws Exception {
        System.out.println(new Date());
        Message message = new Message("Hello");
        byte[] sM = serializeObject(message);
        Message unS = (Message) deserializeObject(sM);
        System.out.println(unS.getRecipientHash());
        System.out.println(new Date());
    }
}
