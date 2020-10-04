package org.secknight.secure_web_app.controllers;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * This is the User Interface which is the default
 * interface for every user that does not have the ADMIN ROLE
 * Please view the documentation below for some authorization
 * examples.
 * NOTE: To use PreAuthorize Filters you must use the annotation
 * @EnableGlobalMethodSecurity(prePostEnabled = true)
 * as demonstrated in class ApplicationSecurityConfig
 * @see org.secknight.secure_web_app.security.ApplicationSecurityConfig
 */
@Controller ("MyControllers.UserUI")
@RequestMapping("/userUI")
class UserUI {

	private static final String template="redirect:/userUI";

	@ModelAttribute
	public void addAttributes(Model model) {
		model.addAttribute("person", new Person());
		model.addAttribute("person2", new Person());
		model.addAttribute("switch", new Switch());
	}

	@GetMapping
	public String home() {return "userUI";}

	/**
	 * Demonstrate how we can restrict access to a
	 * request based on the user`s Role
	 * @param attributes RedirectAttributes
	 * @param person Demonstrate form input mapping to a Java Object
	 * @param bindingResult Error Checking
	 * @return Template
	 */
	@PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id1")
	@PreAuthorize("hasAnyRole('PRIVILEGED_USER')")
	public String authorizedRequest(RedirectAttributes attributes, @ModelAttribute("person") Person person, BindingResult bindingResult)  {
		return handleRequest(attributes, person, bindingResult);
	}

	/**
	 * Demonstrate how we can restrict access to a
	 * request based on the user`s Permissions.
	 * NOTE: According the Database structure (recommended guidelines)
	 * a User is aware only of their Roles and consequently the Roles are mapped
	 * to Permissions. Thus we don`t add Permissions directly to the
	 * Users.
	 * @param attributes RedirectAttributes
	 * @param person Demonstrate form input mapping to a Java Object
	 * @param bindingResult Error Checking
	 * @return Template
	 */
	@PostMapping(consumes={MediaType.APPLICATION_FORM_URLENCODED_VALUE},params = "post_id2")
	@PreAuthorize("hasAnyAuthority('delete')")
	public String authorizedRequest2(RedirectAttributes attributes, @ModelAttribute("person2") Person person, BindingResult bindingResult) {
		return handleRequest(attributes, person, bindingResult);
	}
	/**
	 * Person object is just an example object we chose to
	 * demonstrate that fields mapped as anything but String are by
	 * default secured and handled properly with exceptions if they
	 * are not mapped correctly.
	 * @param attributes RedirectAttributes
	 * @param person Demonstrate form input mapping to a Java Object
	 * @param bindingResult Error Checking
	 * @return Template
	 */
	private String handleRequest(RedirectAttributes attributes, @ModelAttribute("person") Person person, BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			for(FieldError error : bindingResult.getFieldErrors()) {
				String field = error.getField();
				String message = error.getDefaultMessage();
				if (message!=null && message.contains("NumberFormatException")) {
					attributes.addFlashAttribute("errorMessage", "Please enter an Integer in Field " + field);
				}
			}
		}
		else attributes.addFlashAttribute("output","Person: "+person.getId()+" "+person.getName());
		return template;
	}

	/**
	 * Here we demonstrate that although the
	 * Admin URL directory is accessible only
	 * by the User Role Admin, a programming
	 * mistake can lead to Privileged Information
	 * Exposure. The template can still be rendered
	 * and the event will not be logged by our
	 * Audit Manager
	 * @see org.secknight.secure_web_app.audit.AuditManager
	 * @see org.secknight.secure_web_app.security.ApplicationSecurityConfig (Restriction
	 * on Admin URL directory)
	 * @return template
	 */
	@PostMapping(params = "post_id3")
	public String authorizedRequestVulnerable() {
		System.out.println("Vulnerable Request");
		return "adminUI";
	}
}
class Person {
	private String name;
	private Integer id;
	public void setId(Integer id) {
		this.id = id;
	}
	public void setName(String name) {
		this.name = name;
	}
	public Integer getId() {
		return id;
	}
	public String getName() {
		return name;
	}
}
