package org.secknight.secure_web_app.auth;

import java.io.IOException;
import java.util.Collection;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * On Authentication Success redirect
 * to the proper interface (User UI or Admin UI)
 */
@Component ("MyComponents.Auth.AuthSuccessHandler")
public class AuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	@Value( "${admin.page}" )
	private String admin_url;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		setSameSiteCookie(response);
		setDefaultTargetUrl(determineTargetUrl(authentication));
		handle(request, response, authentication);
		clearAuthenticationAttributes(request);
	}

	/**
	 * Redirect to the proper UI depending on the ROLE of the user
	 * @param authentication Authentication Details of the current user
	 * @return Redirection Url
	 */
	private String determineTargetUrl (Authentication authentication) {
		Collection<? extends GrantedAuthority> authorities=authentication.getAuthorities();
		for (GrantedAuthority a: authorities)
			if(a.getAuthority().contentEquals("ROLE_ADMIN")) return admin_url;
		return "/userUI";
	}

	/**
	 * Set SameSite Attribute for all cookies
	 * Unfortunately there is no application property
	 * that handles this feature
	 * @param response Customized Response
	 */
	private void setSameSiteCookie(HttpServletResponse response){
		Collection<String> headers = response.getHeaders(HttpHeaders.SET_COOKIE);
		boolean firstHeader = true;
		for (String header : headers) {
			if (firstHeader) {
				response.setHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, "SameSite=Strict"));
				firstHeader = false;
				continue;
			}
			response.addHeader(HttpHeaders.SET_COOKIE, String.format("%s; %s", header, "SameSite=Strict"));
		}
	}
}
