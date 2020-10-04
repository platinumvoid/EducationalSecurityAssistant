package org.secknight.secure_web_app.database;

import java.util.regex.Pattern;
import org.secknight.secure_web_app.auth.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;

@Service("MyServices.UserDetailsService")
public class ApplicationUserDetailsService implements UserDetailsService {

	private final SQLiteUserDao applicationUserDao;
	private static final String email_regex = "^(.+)@(.+)$";
	private static final Pattern pattern= Pattern.compile(email_regex);
	@Autowired private LoginAttemptService loginAttemptService;

	/**
	 * Change the Qualifier and add a new applicationUserDao for another
	 * database
	 * @param applicationUserDao Database Handler
	 */
	@Autowired
	public ApplicationUserDetailsService(@Qualifier("sqlite_dao")SQLiteUserDao applicationUserDao) {//Qualifier and Autowired in case of mutliple db implementations
		this.applicationUserDao=applicationUserDao;
	}

	/**
	 * Load user by username or email. If the
	 * IP is blocked due to multiple login attempts raise
	 * exception and prevent access
	 * @param username Email or Username
	 * @return Application User
	 * @throws UsernameNotFoundException if the User is not found
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		ApplicationUser user;
		String ip = getClientIP();
		if (loginAttemptService.isIPBlocked(ip)) {
			throw new AuthenticationServiceException("blocked_ip");
		}
		if (pattern.matcher(username).find()) {
			user=applicationUserDao.getUserDetails("",username);
		}else {
			user=applicationUserDao.getUserDetails(username,"");
		}
		if (user==null) {
			throw new UsernameNotFoundException(String.format("Username %s not found", username));
		}
		return user;
	}

	/**
	 * We use the Header X-Forwarded-For because we do not
	 * want to block an entire IP address subnet in case it
	 * is used as a proxy
	 * @return IP Address
	 */
	private String getClientIP() {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		String xfHeader = request.getHeader("X-Forwarded-For");
		if (xfHeader == null){
			return request.getRemoteAddr();
		}
		return xfHeader.split(",")[0];
	}
}
