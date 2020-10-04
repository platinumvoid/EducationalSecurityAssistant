package org.secknight.secure_web_app.error_handling;

public class StorageFileNotFoundException extends StorageException {

public StorageFileNotFoundException(String message) {
        super(message);
        }
public StorageFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
        }

}