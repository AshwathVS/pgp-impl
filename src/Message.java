//package src;

import java.io.*;
import java.util.*;

// class for encapsulating an encrypted and signed message
public class Message implements Serializable {

    private String recipientHash; // SHA-256 hash of recipient userid
    private Date timestamp;       // timestamp (java.util.Date)
    private byte[] key;           // AES key used, encrypted with RSA
    private byte[] iv;            // unencrypted IV
    private byte[] encryptedMsg;  // sender userid + message, encrypted with AES
    private byte[] signature;     // signature of all above

    public Message() {
    }

    public Message(String recipientHash) {
        this.recipientHash = recipientHash;
    }

    public String getRecipientHash() {
        return recipientHash;
    }

    public void setRecipientHash(String recipientHash) {
        this.recipientHash = recipientHash;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getEncryptedMsg() {
        return encryptedMsg;
    }

    public void setEncryptedMsg(byte[] encryptedMsg) {
        this.encryptedMsg = encryptedMsg;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String generateDataToBeSigned() {
        return this.recipientHash + this.timestamp + this.key + this.iv + this.encryptedMsg;
    }

    public static class RequestEnvelope<T> implements Serializable {

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

    public static class ResponseEnvelope<T> implements Serializable {
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

    public static class DecryptedMessage {
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

}