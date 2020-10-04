package org.secknight.secure_web_app.controllers;

import org.secknight.secure_web_app.database.ApplicationUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;
import java.util.*;

@Controller ("MyControllers.AdminUI")
public class AdminUI {

	protected static final Logger LOG = LoggerFactory.getLogger(AdminUI.class.getName());
	@Autowired private SessionRegistry sessionRegistry;
	@Autowired private ApplicationEventPublisher publisher;

	@ModelAttribute
	public void addAttributes(Model model) {
		model.addAttribute("switch", new Switch());
	}

	/**
	 * We are using a random generated string for the
	 * Admin URL directory. This feature is not considered
	 * a security protection. The reason we apply it
	 * is just to hide it from tools like dirbuster
	 * which attempt to map our website. It is also
	 * recommended to create an additional random login
	 * directory where only the admin can login.
	 */
	@Value("${admin.page}")
	private String admin_url;

	/**
	 * We monitor any access to the Admin URL directory
	 * and publish it as an audit event
	 * @see AuditEvent
	 * @param authentication Authentication Details of the user who access this URL
	 * @return template
	 */
	@GetMapping("${admin.page}")
	public String home(Authentication authentication) {
		publisher.publishEvent(new AuditApplicationEvent(new AuditEvent(authentication.getName(),"AUTHORIZATION_REQUEST",
				new HashMap<>(){{
			put("url_source", admin_url);
			put("authorities", authentication.getAuthorities());
			WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
			put("ip_address", details.getRemoteAddress());
			put("session_id", details.getSessionId());
		}})));
		return "adminUI";
	}
	/**
	 * The Switch User functionality is handle by the
	 * bean in ApplicationSecurityConfig class. This
	 * directory is in case the functionality failed
	 * due to the targeted user does not exist.
	 * @see org.secknight.secure_web_app.security.ApplicationSecurityConfig
	 */
	@GetMapping("/switchUser")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public RedirectView setErrorMessageSwitch(RedirectAttributes attributes) {
		attributes.addFlashAttribute("errorMessage", "Username not Found");
		return new RedirectView(admin_url);
	}

	/**
	 * Retrieves all the current logged in users
	 * using the Session Registry and logs them
	 * in a special log file.
	 * @return Template
	 */
	@PostMapping(value="${admin.page}",params = "status")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public String getUsers() {
		StringBuilder users_list=new StringBuilder();
		List<Object> applicationUsers=sessionRegistry.getAllPrincipals();
		applicationUsers.forEach((temp) -> {
			users_list.append("\nUser: ").append(((ApplicationUser) temp).getUsername()).append("\n");
			Collection<? extends GrantedAuthority> grantedAuthorities=((ApplicationUser)temp).getAuthorities();
			if (grantedAuthorities!=null && grantedAuthorities.size()>0){
				users_list.append("\tAuthorities:\n");
				for (GrantedAuthority grantedAuthority : grantedAuthorities) {
					users_list.append("\t\t").append(grantedAuthority.getAuthority()).append("\n");
				}
			}
			users_list.append("\tSession ID:\n");
			List<SessionInformation> session_inf=sessionRegistry.getAllSessions(temp,true);
			session_inf.forEach((temp2)-> users_list.append("\t\t").append(temp2.getSessionId()).append(" ").append(temp2.isExpired()).append("\n"));
		});
		LOG.info(users_list.toString());
		return "adminUI";
	}
}
class Switch {
	private String username;
	public void setUsername(String username) {this.username = username;}
	public String getUsername() {return username;}
}