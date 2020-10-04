package org.secknight.secure_web_app.security;

import java.util.concurrent.TimeUnit;
import org.apache.catalina.filters.RemoteAddrFilter;
import org.secknight.secure_web_app.auth.LoginAttemptService;
import org.secknight.secure_web_app.database.ApplicationDaoAuthenticationProvider;
import org.secknight.secure_web_app.database.ApplicationUserDetailsService;
import org.secknight.secure_web_app.auth.AuthFailureHandler;
import org.secknight.secure_web_app.auth.AuthSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.context.request.RequestContextListener;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //required for the PreAuthorize filters as demonstrated in the UserUI controller.
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired private ApplicationUserDetailsService applicationUserService;
	@Autowired private PasswordEncoder passwordEncoder;
	@Autowired private AuthFailureHandler authFailureHandler;
	@Autowired private AuthSuccessHandler authSuccessHandler;
	@Autowired private LoginAttemptService loginAttemptService;

	@Value( "${server.servlet.session.cookie.name}" ) private String session_cookie_name;
	@Value( "${remember.me.cookie.name}" ) private String remember_me_cookie_name;
	@Value( "${remember.me.hash.key}" ) private String remember_me_hash_key;
	@Value( "${admin.page}" ) private String admin_url;

	@Override
	protected void configure(final HttpSecurity http) throws Exception{
		http
				/*
				 * If your application does not accept request from a browser then
				 * CSRF is not needed. But otherwise it is crucial to be enabled (by default
				 * with Spring Boot).
				 * .csrf().disable()
				 */
				.csrf().csrfTokenRepository(new HttpSessionCsrfTokenRepository())
		.and()
				/*AUTHORIZATION*/
				.authorizeRequests()

					/*
					 * NOTE: Order of antMatchers matters. Top-Bottom -> General Rules to More Specific
					 */
					/* ADD PUBLICLY ACCESSIBLE DIRECTORIES (eg. css, images etc)*/
					.antMatchers("/","/css/*","/images/**","/js/*","/index.html","/login","/register").permitAll()
					/* AUTHENTICATE ALL REQUESTS*/
					//.anyRequest().authenticated()
					/* ADD IP BASED DIRECTORIES - SECURE ADMIN PAGE*/
					.antMatchers(admin_url+"/**","/impersonate","/actuator","/switchUser").hasIpAddress("127.0.0.1")
					/* ADD AUTHENTICATED ONLY DIRECTORIES*/
					.antMatchers(admin_url+"/**","/userUI/**").authenticated()
					/* ADD AUTHORIZATION BASED DIRECTORIES*/
					.antMatchers(admin_url+"/**","/impersonate","/actuator","/switchUser").hasAnyRole("ADMIN")
		.and()
				/* FORM LOGIN*/
				.formLogin()
					.loginPage("/login")
					.successHandler(authSuccessHandler)
					.failureHandler(authFailureHandler)
					.passwordParameter("password") //name input in HTML
					.usernameParameter("username") //name input in HTML
		.and()
				/* REMEMBER ME COOKIE*/
				.rememberMe()
					.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))// default 2 weeks
					.key(remember_me_hash_key)
					.rememberMeParameter("remember-me") //name input in HTML
					.rememberMeCookieName(remember_me_cookie_name)
					.useSecureCookie(true)
					.userDetailsService(applicationUserService)
		.and()
				/* LOGOUT*/
				.logout()
					.logoutUrl("/logout")
					/* All change state requests, must be POST to protect from CSRF*/
					.clearAuthentication(true)
					.invalidateHttpSession(true)
					/* ENSURE TO DELETE ALL COOKIES*/
					.deleteCookies(session_cookie_name,remember_me_cookie_name,"XSRF-TOKEN")
					.logoutSuccessUrl("/")
		.and()
				/*SESSIONS*/
				.sessionManagement()
				/*
				* If over 10 sessions per user then the oldest session is expired
				* By adding the following setting you opt to prevent any additional same
				* users to access the site, if there currently 10 sessions active
				* .maxSessionsPreventsLogin(true)
				*
				* SessionFixationProtection
				* Session fixation is a vulnerability caused by incorrectly handling
				* user sessions in a Web application. A user’s session is usually tracked
				* by a cookie, which is assigned when the user visits the page with the Web
				*  application for the first time. The problem occurs when this cookie does not
				* change for the duration of the browsing session; users authenticate and log out,
				* but their session cookie remains the same. By default Spring MVC protects us by
				* changing the session when it is required.
				* */
				.maximumSessions(10)
				.sessionRegistry(sessionRegistry())
				.expiredUrl("/login")
				.and()
				.invalidSessionUrl("/login")
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
		;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth){
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	@Bean
	public ApplicationDaoAuthenticationProvider daoAuthenticationProvider() {
		ApplicationDaoAuthenticationProvider provider = new ApplicationDaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() { return new HttpSessionEventPublisher(); }

	@Bean
	public RequestContextListener requestContextListener(){ return new RequestContextListener(); }

	@Bean
	public SessionRegistry sessionRegistry() { return new SessionRegistryImpl(); }

	/**
	 * Feature that allows the user ADMIN to access
	 * resources in the web application as another user
	 * with less privileges. The reason is when we want
	 * to access a resource related with a 3rd party application
	 * ,for instance send an email, which may be potentially vulnerable
	 * we do not want to expose our fully privileged user.
	 * @return SwitchUserFilter
	 */
	@Bean
	public SwitchUserFilter switchUserFilter() {
		SwitchUserFilter filter = new SwitchUserFilter();
		filter.setUserDetailsService(applicationUserService);
		filter.setSwitchUserUrl("/impersonate");
		filter.setSwitchFailureUrl("/switchUser");
		filter.setTargetUrl("/userUI");
		return filter;
	}

	/**
	 * Application Firewall
	 * Whitelist or Blacklist desired IP addresses
	 * @return FilterRegistrationBean
	 */
	@Bean
	public FilterRegistrationBean<RemoteAddrFilter> remoteAddressFilter() {
		FilterRegistrationBean<RemoteAddrFilter> filterRegistrationBean = new FilterRegistrationBean<>();
		RemoteAddrFilter filter = new RemoteAddrFilter();
		filter.setAllow(".*");
		filter.setDeny("192.168.0.3");
		filter.setDenyStatus(403);
		filterRegistrationBean.setFilter(filter);
		filterRegistrationBean.addUrlPatterns("/*");
		return filterRegistrationBean;
	}

	/**
	 * Another way to block IP Addresses that are attempting a brute-force attack
	 * Pros: You can block the entire website or select
	 * which directories will be blocked
	 * Cons: Cannot invalidate keys in case of a successful authentication
	 * as the client will not have access to the login page
	 * @return FilterRegistrationBean
	 */
	@Bean
	public FilterRegistrationBean<LoginAttemptFilter> loginAttemptFilter(){
		FilterRegistrationBean<LoginAttemptFilter> registrationBean= new FilterRegistrationBean<>();
		registrationBean.setFilter(new LoginAttemptFilter(loginAttemptService));
		registrationBean.addUrlPatterns("/*");
		return registrationBean;
	}
}
