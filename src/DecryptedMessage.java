import java.util.Date;

public class DecryptedMessage {
    private String senderUserId;

    private String message;

    private boolean isSignatureVerified;

    private Date dateSent;

    public String getSenderUserId() {
        return senderUserId;
    }

    public void setSenderUserId(String senderUserId) {
        this.senderUserId = senderUserId;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isSignatureVerified() {
        return isSignatureVerified;
    }

    public void setSignatureVerified(boolean signatureVerified) {
        isSignatureVerified = signatureVerified;
    }

    public Date getDateSent() {
        return dateSent;
    }

    public void setDateSent(Date dateSent) {
        this.dateSent = dateSent;
    }

    public void printMessage() {
        System.out.println(this.senderUserId + "'s message:");
        System.out.println(this.message);
        System.out.println(this.dateSent);
    }
}
