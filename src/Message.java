package src;

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
}