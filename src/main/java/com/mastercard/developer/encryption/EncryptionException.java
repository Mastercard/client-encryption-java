package com.mastercard.developer.encryption;

public class EncryptionException extends Exception {

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncryptionException(String message) {
        super(message);
    }
}
