package org.secknight.secure_web_app.controllers.vulnerabilities;

import java.io.*;
import java.net.MalformedURLException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import com.google.common.base.CharMatcher;
import org.apache.commons.io.FilenameUtils;
import org.secknight.secure_web_app.controllers.validators.upload.*;
import org.secknight.secure_web_app.error_handling.StorageException;
import org.secknight.secure_web_app.error_handling.StorageFileNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import javax.xml.bind.DatatypeConverter;

/**
 * Used to demonstrate File Upload
 * and Path Traversal vulnerabilities.
 */
@Service ("MyServices.FileSystemStorageService")
public class FileSystemStorageService{
    private static final Logger LOG = LoggerFactory.getLogger(FileSystemStorageService.class);
    private final Path rootLocation= Paths.get("upload-dir");
    private final Path tmp_rootLocation=Paths.get("upload-tmp-dir");
    //Set the Maximum Size according to your preferences, but it is important there is an upper limit
    //to prevent Denial of Service
    private final static int MAX_SIZE=1000000;
    //Limit the filename length (for NTFS less than 255 characters)
    private final static int MAX_NAME_LENGTH=254;

    /**
     * Stores the uploaded file in the designated directory.
     * Based on the validation a secure approach will be used if
     * it is set to true otherwise the vulnerable approach.
     * @param file File to be uploaded
     * @param validation Secure (true) or Vulnerable (false) approach
     * @return Hash value of the file if successfully uploaded otherwise
     * returns an error message
     */
    public UploadStatus store(MultipartFile file,Boolean validation) {
        try {
            if (file==null || file.isEmpty() || file.getOriginalFilename() == null ||
                    file.getContentType() == null || file.getSize() == 0){
                return new UploadStatus("File is Empty",false);
            }

            //Ensure the Upload directories exist
            createDirectories();

            //Secured File Upload
            if (validation)
                return checkValidation(StringUtils.cleanPath(file.getOriginalFilename()), file.getSize(), file.getContentType(),  multipleRead(file.getInputStream()));

            //Vulnerable File Upload: Blindly upload file without any form of preprocessing or validation
            Files.copy(file.getInputStream(), this.rootLocation.resolve(StringUtils.cleanPath(file.getOriginalFilename())), StandardCopyOption.REPLACE_EXISTING);
            /*We send to the user the hash to validate the file and to prevent XSS attacks by
            displaying the filename on browser.*/
            return new UploadStatus(getHash(file.getOriginalFilename()),true);

        }
        catch (IOException | StorageException | NoSuchAlgorithmException e) {
            return new UploadStatus("Something internally went wrong",false);
        }
    }

    /**
     * Calculate the SHA256 hash of the uploaded file.
     * We sent to the user the hash value to prevent XSS attacks using
     * the file name.
     * @param filename File Name
     * @return Hash value
     * @throws NoSuchAlgorithmException if the hash algorithm does not exist
     * @throws IOException if the file is not found or is corrupted
     */
    private String getHash(String filename) throws NoSuchAlgorithmException, IOException {
        byte[] content = Files.readAllBytes(this.rootLocation.resolve(filename));
        MessageDigest digester = MessageDigest.getInstance("sha-256");
        byte[] hash = digester.digest(content);
        return DatatypeConverter.printHexBinary(hash);
    }

    /**
     * Save InputStream in Byte Array for multiple reads as
     * InputStream can be only read once
     * (Create tempFile and actual File)
     * @param inputStream InputStream
     * @return byte[]
     * @throws IOException Exception
     */
    private byte[] multipleRead(InputStream inputStream) throws IOException {
        byte[] buffer = new byte[2048];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int byteCount;
        while ((byteCount = inputStream.read(buffer)) != -1)
        {
            output.write(buffer, 0, byteCount);
        }
        return output.toByteArray();
    }

    /**
     * Performs a series of checks to determine if the file is safe to be
     * stored in the upload directory.
     * Checks:
     * 1. Prevent DDoS attacks and Path Traversal Attacks (..)
     * 2. Size and File Name length
     * 3. Check extension
     * 4. Check request Content-Type
     * 5. Check the actual contents of the file to determine its validity
     * Note:
     *
     * @param filename File Name
     * @param size File Size
     * @param content_type Request Content-type
     * @param source Byte Array of the file
     * @return Status of the Upload
     * @throws IOException IOException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     */
    private UploadStatus checkValidation(String filename, long size, String content_type, byte[] source)
            throws IOException, NoSuchAlgorithmException {

        /*Prevent Uploading a file in Windows with invalid characters such as |<>*?” in its name.
        This may show interesting error messages that can lead to information disclosure. In addition
        Prevent alternate data stream usage*/
        if (filename.contains(":")|| filename.contains("|") || filename.contains("?")||filename.contains("*")
        || filename.contains("<") || filename.contains(">")|| filename.contains("\"") || !CharMatcher.ascii().matchesAllOf(filename)) {
            return new UploadStatus("File is invalid",false);
        }

        /* Prevent Path Traversal Attacks   Linux                      Windows       */
        if (filename.contains("..")      || filename.contains("/")  || filename.contains("\\")) {
            return new UploadStatus("File is invalid",false);
        }
        /*
        * Please view this link for additional Windows Protections
        * https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
        */

        //Prevent DDoS attacks
        if (filename.length()>=MAX_NAME_LENGTH && size>=MAX_SIZE) {
            return new UploadStatus("File is invalid",false);
        }

        //Accept only desired extensions and lower case only
        if(!FilenameUtils.getExtension(filename).matches("png|jpg|jpeg|docx|doc|pdf|txt")){
            return new UploadStatus("Accepted extensions are: <br> png,jpg,jpeg,docx,doc,pdf,txt",false);
        }

        //Accept only desired content_types
        if (!content_type.matches("text/plain|application/pdf|image/png|image/jpeg|application/msword|application/vnd\\.openxmlformats-officedocument\\.wordprocessingml\\.document")){
            return new UploadStatus("Invalid Content Type",false);
        }

        //Create a temporary File to be inspected and validated
        File tmpFile= File.createTempFile("uploaded-", null,new File("./upload-tmp-dir"));
        Path tmpPath = tmpFile.toPath();
        InputStream is = new ByteArrayInputStream(source);
        long copiedBytesCount = Files.copy(is,tmpPath, StandardCopyOption.REPLACE_EXISTING);
        if (copiedBytesCount != size) {
            throw new IOException(String.format("Error during stream copy to temporary disk (copied: %s / expected: %s !", copiedBytesCount, size));
        }

        /*
         * Use the upload validators to determine if the file
         * is actually what it is advertised on its extension
         * Use ExcelDocumentDetectorImpl for Excel files
         * Use PowerpointDocumentDetectorImpl for PowerPoint files
         */
        boolean isSafe;
        DocumentDetector documentDetector;
        switch(FilenameUtils.getExtension(filename)){
            case "pdf" -> {
                documentDetector = new PdfDocumentDetectorImpl();
                isSafe = documentDetector.isSafe(tmpFile);
            }
            case "doc","docx" -> {
                documentDetector = new WordDocumentDetectorImpl();
                isSafe = documentDetector.isSafe(tmpFile);
            }
            case "png","jpeg", "jpg" -> {
                DocumentSanitizer documentSanitizer = new ImageDocumentSanitizerImpl();
                isSafe = documentSanitizer.madeSafe(tmpFile);
            }
            case "txt" -> isSafe=true;
            default -> isSafe=false;
        }

        // The file is Safe therefore we store it in upload_dir to be able to serve it
        if (isSafe){
            is = new ByteArrayInputStream(source);
            copiedBytesCount = Files.copy(is, this.rootLocation.resolve(filename), StandardCopyOption.REPLACE_EXISTING);
            if (copiedBytesCount != size) {
                throw new IOException(String.format("Error during stream copy to temporary disk (copied: %s / expected: %s !", copiedBytesCount, size));
            }
            // If it is not safe we dont delete the tmpFile to inspect it for malware in a Virtual Environment
            safelyRemoveFile(tmpPath);
            return new UploadStatus(getHash(filename),true);
        }

        LOG.warn("Detection of a unsafe file upload or cannot sanitize uploaded document: "+filename);
        return new UploadStatus("File is malformed or contains malware",false);
    }


    /**
     * Creates the upload directories if they
     * are not already exist.
     * upload-dir: Directory where files are accessible to the clients
     * upload-tmp-dir: Directory to examine files before serving them,
     * If they are safe the temporary file is deleted and the a copy of
     * the file is made on the serving directory. Otherwise if they contain
     * malware they remain to this directory to be examined further.
     * NOTE: Use a safe environment like a Virtual Machine to analyze files
     * for malware (DO NOT open or run directly on the personal computer or
     * server)
     */
    private void createDirectories() {
        try {
            Files.createDirectories(rootLocation);
            Files.createDirectories(tmp_rootLocation);
        }
        catch (IOException e) {
            LOG.warn("Could not initialize storage");
            throw new StorageException("Could not initialize storage", e);
        }
    }

    private static void safelyRemoveFile(Path p) {
        try {
            if (p != null) {
                // Remove temporary file
                if (!Files.deleteIfExists(p)) {
                    // If remove fail then overwrite content to sanitize it
                    Files.writeString(p, "-", StandardOpenOption.CREATE);
                }
            }
        } catch (Exception e) {
            LOG.warn("Cannot safely remove file: " + p.getFileName());
        }
    }

    public Stream<Path> loadAll() {
        try {
            return Files.walk(this.rootLocation, 1)
                    .filter(path -> !path.equals(this.rootLocation))
                    .map(this.rootLocation::relativize);
        }catch (IOException e) {
            throw new StorageException("Failed to read stored files", e);
        }
    }

    public Resource loadAsResource(String filename) {
        Resource resource;
        try {
            createDirectories();
            Path file =  rootLocation.resolve(filename);
            resource = new UrlResource(file.toUri());
            if (resource.exists() || resource.isReadable()) {
                return resource;
            }else{
                LOG.warn("Could not read file: " + filename);
                throw new StorageFileNotFoundException("Could not find file");
            }
        }
        catch (MalformedURLException malformedURLException) {
            LOG.warn("Could not read file: " + filename);
            throw new StorageFileNotFoundException("Could not find file");
        }
    }
}
class UploadStatus{
    private final String message;
    private final Boolean status;
    public UploadStatus(String message, Boolean status) {
        this.message = message;
        this.status = status;
    }
    public String getMessage() {
        return message;
    }
    public Boolean getStatus() {
        return status;
    }
}