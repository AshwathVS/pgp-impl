public class DecryptedMessage {
    private String senderUserId;

    private String message;

    private boolean isSignatureVerified;

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
}
