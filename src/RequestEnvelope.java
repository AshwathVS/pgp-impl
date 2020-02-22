import java.io.Serializable;

public class RequestEnvelope<T> implements Serializable {

    private T messageObject;

    private EnumRequestType messageType;

    public RequestEnvelope(T messageObject, EnumRequestType messageType) {
        this.messageObject = messageObject;
        this.messageType = messageType;
    }

    public RequestEnvelope() {
    }

    public T getMessageObject() {
        return messageObject;
    }

    public void setMessageObject(T messageObject) {
        this.messageObject = messageObject;
    }

    public EnumRequestType getMessageType() {
        return messageType;
    }

    public void setMessageType(EnumRequestType messageType) {
        this.messageType = messageType;
    }

    public static enum EnumRequestType {
        READ,
        WRITE,;
    }
}
