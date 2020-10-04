package org.secknight.secure_web_app.controllers.vulnerabilities;

import com.google.common.base.CharMatcher;
import org.apache.commons.io.FilenameUtils;
import org.secknight.secure_web_app.error_handling.StorageFileNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/path-interface")
public class PathTraversal {

    @Autowired private FileSystemStorageService storageService;

    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("secure", new Input());
        model.addAttribute("vulnerable", new Input());
    }

    @GetMapping
    public String home() { return "path"; }


    @GetMapping(value="/files",produces = MediaType.ALL_VALUE)
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@RequestParam(required = false) String filename) {

        return getResourceResponseEntity(filename);
    }

    /**
     * We block the use of .. so the attacker cannot
     * access files outside the designated directory
     * In addition we block directory symbols which
     * differ in Windows and Linux OS.
     * Finally we block the use of Alternate Data
     * Streams in Windows by blocking the symbol ":"
     * See the following class for more url encoding
     * protections.
     * @see  org.springframework.security.web.firewall.StrictHttpFirewall
     * @param secure Secure Input
     * @param bindingResult Error Checker
     * @return File as a Resource
     */
    @PostMapping(produces = MediaType.ALL_VALUE,params = "post_id1")
    @ResponseBody
    public ResponseEntity<Resource> serveFileSecure(@ModelAttribute("secure") Input secure, BindingResult bindingResult) {
        if (bindingResult.hasErrors() || secure==null || secure.getInput().contentEquals("")) {
            throw new StorageFileNotFoundException("File not Found");
        }
        /* Prevent  Path Traversal Attacks   Linux                   Windows                  Windows alternate data stream */
        if (secure.getInput().contains("..")||secure.getInput().contains("/")||secure.getInput().contains("\\")||secure.getInput().contains(":") || !CharMatcher.ascii().matchesAllOf(secure.getInput())){
            // Malicious attempt to read file outside the upload directory
            throw new StorageFileNotFoundException("File not Found");
        }
        return getResourceResponseEntity(secure.getInput());
    }

    @PostMapping(produces = MediaType.ALL_VALUE,params = "post_id2")
    @ResponseBody
    public ResponseEntity<Resource> serveFileVulnerable(@ModelAttribute("vulnerable") Input vulnerable, BindingResult bindingResult) {
        if (bindingResult.hasErrors() || vulnerable==null || vulnerable.getInput().contentEquals("")) {
            throw new StorageFileNotFoundException("File not Found");
        }
        System.out.println(vulnerable.getInput());

        return getResourceResponseEntity(vulnerable.getInput());
    }

    private ResponseEntity<Resource> getResourceResponseEntity(String input) {
        Resource file = storageService.loadAsResource(input);
        HttpHeaders headers = new HttpHeaders();
        switch (FilenameUtils.getExtension(input)){
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

}