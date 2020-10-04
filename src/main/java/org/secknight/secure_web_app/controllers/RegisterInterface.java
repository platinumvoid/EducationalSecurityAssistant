package org.secknight.secure_web_app.controllers;

import org.secknight.secure_web_app.database.SQLiteUserDao;
import org.secknight.secure_web_app.controllers.validators.registration.RegUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;
import javax.validation.Valid;
import java.util.Objects;

@Controller ("MyControllers.RegisterInterface")
@RequestMapping("/register")
class RegisterInterface {

    @Autowired private SQLiteUserDao database;

    @ModelAttribute
    public void addAttributes(Model model) {
        model.addAttribute("registerUser", new RegUser());
    }

    @GetMapping
    public String home() {return "register";}

    /**
     * Registers a new User with ROLE USER if all
     * the fields are validated. We enforce usage
     * of strong passwords, valid email addresses
     * and usernames without special symbols (to
     * prevent possible XSS attacks when username
     * is displayed on the website)
     * @param attributes Redirect attributes
     * @param register_user User Details
     * @param bindingResult Error Checking
     * @return Template
     */
    @PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public RedirectView register_new(RedirectAttributes attributes, @ModelAttribute("register_user") @Valid RegUser register_user, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            for(ObjectError error : bindingResult.getAllErrors()) {
                String[] lines = Objects.requireNonNull(error.getDefaultMessage()).split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (line.startsWith("Email:")) {
                        attributes.addFlashAttribute("error_email", line.substring(6));
                    }else if (line.startsWith("Username:")) {
                        attributes.addFlashAttribute("error_user", line.substring(9));
                    }else if (line.startsWith("Password:")) {
                        attributes.addFlashAttribute("error_password", line.substring(9));
                    }else if (line.startsWith("Retype:")) {
                        attributes.addFlashAttribute("error_retype", line.substring(7));
                    }
                }
            }
            return new RedirectView("register");
        }

        if(database.checkIfUserExists(register_user.getUsername(), register_user.getEmail())){
            attributes.addFlashAttribute("error_auth","Username or Email already exists");
            return new RedirectView("register");
        }

        int status=database.registerNewUser(register_user.getUsername(),register_user.getEmail(),register_user.getPassword());
        if (status==0){
           attributes.addFlashAttribute("error_auth","Something went wrong");
           return new RedirectView("register");
        }
        return new RedirectView("login");
    }
}
