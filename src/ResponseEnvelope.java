import java.io.Serializable;

public class ResponseEnvelope<T> implements Serializable {
    private T responseObject;

    private EnumResponseStatus responseStatus;

    public ResponseEnvelope(T responseObject, EnumResponseStatus responseStatus) {
        this.responseObject = responseObject;
        this.responseStatus = responseStatus;
    }

    public ResponseEnvelope() {
    }

    public T getResponseObject() {
        return responseObject;
    }

    public void setResponseObject(T responseObject) {
        this.responseObject = responseObject;
    }

    public EnumResponseStatus getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(EnumResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
    }

    public static enum EnumResponseStatus {
        OK,
        ERROR;
    }
}
