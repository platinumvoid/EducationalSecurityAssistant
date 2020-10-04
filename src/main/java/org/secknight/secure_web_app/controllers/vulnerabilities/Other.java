package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/other-interface")
public class Other {

    private static final Logger LOG = LoggerFactory.getLogger(Other.class);

    @GetMapping
    public String home() { return "other"; }

    /**
     * INSECURE REDIRECT
     * -----------------
     * Here you if you need to redirect based on an event (client-side)
     * it is better to send a random variable instead and based on that
     * you will redirect rather than using the url itself.
     * Ex.
     * Login-Failed: Send integer 1
     * Login-Succeeded: Send integer 0
     *
     * If the input is 1 redirect to login page with error message
     * or if input is 0 redirect to the appropriate user interface
     * @param url Url to redirect to
     * @return Url
     */
    @GetMapping("/redirect")
    public String insecureRedirect(@RequestParam(required = false) String url) {
        if (url!=null){
            return "redirect:"+url;
        }
        return "redirect:/other-interface";
    }

    /**
     * This is just for information purposes. If a request has
     * multiple parameters of the same name then Spring Boot
     * concatenates them using a comma (,).
     * @param attributes Redirect Attributes
     * @param input Input
     * @return template
     */
    @GetMapping("/http-pollution")
    public String httpPollution(RedirectAttributes attributes, @RequestParam(required = false) String input) {
        if (input!=null && !input.contentEquals("")){
           attributes.addFlashAttribute("output",input);
        }
        return "redirect:/other-interface";
    }

    /**
     * An attacker can add fake entries
     * to a log file that monitors user
     * input
     * @param input Input
     * @return template
     */
    @GetMapping("/crlf-injection")
    public String crlfInjection(@RequestParam(required = false) String input) {
        if (input!=null && !input.contentEquals("")){
           LOG.info(input);
        }
        return "redirect:/other-interface";
    }
}