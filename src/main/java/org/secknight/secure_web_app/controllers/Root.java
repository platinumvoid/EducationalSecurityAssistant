package org.secknight.secure_web_app.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller ("MyControllers.Root")
@RequestMapping("/")
public class Root {

	@GetMapping("login")
	public String home() {return "login";}

	@GetMapping("login-error")
	public String setErrorMessage(RedirectAttributes attributes) {
		attributes.addFlashAttribute("errorMessage", "Username or Password is invalid");
		return "redirect:/login";
	}
}


