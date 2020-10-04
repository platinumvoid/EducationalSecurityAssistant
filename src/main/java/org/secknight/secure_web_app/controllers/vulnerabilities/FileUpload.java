package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.apache.commons.io.FilenameUtils;
import org.secknight.secure_web_app.error_handling.StorageFileNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.MvcUriComponentsBuilder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/upload-interface")
public class FileUpload {

    private static final String template="redirect:/upload-interface";

    @Autowired
    private FileSystemStorageService storageService;

    @GetMapping()
    public String home(Model model) {
        List <String> uri_list=storageService.loadAll().map(
                path ->MvcUriComponentsBuilder.fromMethodName(FileUpload.class,
                        "serveFile", path.getFileName().toString()).build().toUri().toString())
                .collect(Collectors.toList());
        List<DisplayElement> displayElementList=new ArrayList<>();
        for (String uri: uri_list) {
            displayElementList.add(new DisplayElement(uri,uri.split("/")[5]));
        }
        model.addAttribute("files",displayElementList);
        return "upload";
    }

    @GetMapping(value="/files/{filename:.+}",produces = MediaType.ALL_VALUE)
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) {
        if (filename.contentEquals("")){
            throw new StorageFileNotFoundException("File not Found");
        }
        HttpHeaders headers = new HttpHeaders();
        Resource file = storageService.loadAsResource(filename);
        switch (FilenameUtils.getExtension(filename)){
            case "jpg","jpeg"->  headers.setContentType(MediaType.IMAGE_JPEG);
            case "gif" ->  headers.setContentType(MediaType.IMAGE_GIF);
            case "png" -> headers.setContentType(MediaType.IMAGE_PNG);
            case "pdf" ->  headers.setContentType(MediaType.APPLICATION_PDF);
            case "txt" -> headers.setContentType(MediaType.TEXT_PLAIN);
            case "doc" -> headers.setContentType(MediaType.valueOf("application/msword"));
            case "docx" ->  headers.setContentType(MediaType.valueOf("application/vnd.openxmlformats-officedocument.wordprocessingml.document"));

        }


        return new ResponseEntity<>(file, headers, HttpStatus.OK);
    }

    @PostMapping(params = "post_id1")
    public String secured(@RequestParam("file") MultipartFile file,RedirectAttributes redirectAttributes) {

        UploadStatus status=storageService.store(file,true);
        if (status.getStatus()){
            redirectAttributes.addFlashAttribute("output","File Uploaded Successfully: <br>" +
                    status.getMessage() + "<br>(SHA256)");
        }else{
            redirectAttributes.addFlashAttribute("output",status.getMessage());
        }
        return template;
    }
    @PostMapping(params = "post_id2")
    public String vulnerable(@RequestParam("file") MultipartFile file,RedirectAttributes redirectAttributes) {
        UploadStatus status=storageService.store(file,false);
        if (status.getStatus()){
            redirectAttributes.addFlashAttribute("output","File Uploaded Successfully: <br>" +
                    status.getMessage() + "<br>(SHA256)");
        }else{
            redirectAttributes.addFlashAttribute("output",status.getMessage());
        }
        return template;
    }
}

class DisplayElement {
    private String uri;
    private String file;
    public void setUri(String uri) {this.uri = uri;}
    public void setFile(String file) {this.file = file;}
    public String getFile() {return file;}
    public String getUri() {return uri;}

    public DisplayElement(String uri,String file){
        this.uri=uri;
        this.file=file;
    }
}