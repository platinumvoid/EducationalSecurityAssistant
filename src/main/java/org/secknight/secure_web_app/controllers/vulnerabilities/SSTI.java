package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/ssti-interface")
public class SSTI{

    private static final Logger LOG = LoggerFactory.getLogger(SSTI.class);
    private static final String template="redirect:/ssti-interface";

    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("secure", new Input());
        model.addAttribute("vulnerable", new Input());
    }

    @GetMapping
    public String home() {
        return "ssti";
    }

    /**
     * Here we prevent any attempt for executing arbitrary
     * code on the system. It does not cover all possible
     * scenarios so it is not advised to use dynamic
     * output where there is a possibility it can be
     * controlled in any way by a user.
     * Please see the ssti.html for more information as this
     * vulnerability is template related and not with the
     * actual code.
     * @param attributes RedirectAttributes
     * @param secure Normal Input
     * @param bindingResult Error Checking
     * @return html page
     */
    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id1")
    public String secured(RedirectAttributes attributes, @ModelAttribute("secure") Input secure, BindingResult bindingResult)  {
        if (bindingResult.hasErrors())
            for(FieldError error : bindingResult.getFieldErrors())
                LOG.warn(error.getField()+" "+error.getDefaultMessage());
        else {
            //Must not contain space otherwise it will result to an Internal Server Error
            if (secure.getInput().contains("getRuntime") ||secure.getInput().contains("exec") || secure.getInput().contains(" ")){
                LOG.warn("Malicious SSTI attempt: "+secure.getInput());
                attributes.addFlashAttribute("output", "InvalidInput");
            }
            else attributes.addFlashAttribute("output", secure.getInput());

        }
        return template;
    }

    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id2")
    public String vulnerable(RedirectAttributes attributes, @ModelAttribute("vulnerable") Input vulnerable, BindingResult bindingResult)  {
       if (bindingResult.hasErrors())
           for(FieldError error : bindingResult.getFieldErrors())
               LOG.warn(error.getField()+" "+error.getDefaultMessage());
        else attributes.addFlashAttribute("output", vulnerable.getInput());
        return template;
    }
}