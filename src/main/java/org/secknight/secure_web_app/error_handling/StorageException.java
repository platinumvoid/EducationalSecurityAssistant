package org.secknight.secure_web_app.error_handling;

public class StorageException extends RuntimeException {

    public StorageException(String message) {
        super(message);
    }
    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}