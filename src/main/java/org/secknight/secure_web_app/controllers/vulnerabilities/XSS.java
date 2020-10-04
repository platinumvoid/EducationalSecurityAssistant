package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.owasp.html.Sanitizers;
import org.owasp.html.PolicyFactory;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/xss-interface")
public class XSS {

    private static final Logger LOG = LoggerFactory.getLogger(XSS.class);
    private static final String template="redirect:/xss-interface";
    @Autowired private CommentService commentService;

    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("secure", new Input());
        model.addAttribute("vulnerable", new Input());
        model.addAttribute("comments", commentService.getList());
    }

    /**
     * Example of Reflective XSS attack through the query
     * parameter input. On visiting the URL without the
     * query or with a normal input the script is not in effect.
     * @param model XSS Model
     * @param input Vulnerable query parameter
     * @return html page
     */
    @GetMapping
    public String home(ModelMap model, @RequestParam(required = false) String input) {
        if (input!=null) model.addAttribute("output", input);
        return "xss";
    }

    /**
     * Secure Input where we sanitize it
     * before we store. We are using
     * OWASP html sanitizer. The Policy Factory
     * can be customize to select the behavior
     * when malicious payloads have been identified.
     * Default: Block and return empty String
     * @param model XSS Model
     * @param secure Secure input
     * @param bindingResult Error Checker
     * @return html page
     */
    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id1")
    public String secured(ModelMap model, @ModelAttribute("secure") Input secure, BindingResult bindingResult)  {
        if (bindingResult.hasErrors()) {
            for(FieldError error : bindingResult.getFieldErrors())
                LOG.warn(error.getField()+" "+error.getDefaultMessage());
        }else {
            PolicyFactory sanitizer = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);
            String cleanResults = sanitizer.sanitize(secure.getInput());
            commentService.add(new Comment(cleanResults));
            model.addAttribute("comments", commentService.getList());
        }
        return template;
    }

    /**
     * Here we add the vuln_input straight into
     * the commentService without sanitizing
     * it first.
     * @param attributes XSS Model
     * @param vulnerable Vulnerable input
     * @param bindingResult Error Checker
     * @return html page
     */
    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id2")
    public String vulnerable(RedirectAttributes attributes, @ModelAttribute("vulnerable") Input vulnerable, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            for(FieldError error : bindingResult.getFieldErrors())
                LOG.warn(error.getField()+" "+error.getDefaultMessage());
        }else {
            commentService.add(new Comment(vulnerable.getInput()));
            attributes.addFlashAttribute("comments", commentService.getList());
        }
        return template;
    }

    /**
     * Deletes all comments stored in the
     * comment service
     * @param attributes RedirectAttributes
     * @return template
     */
    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "reset")
    public String reset(RedirectAttributes attributes) {
        commentService.reset();
        attributes.addFlashAttribute("comments", commentService.getList());
        return template;
    }
}

