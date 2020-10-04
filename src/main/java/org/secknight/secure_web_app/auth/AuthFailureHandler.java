package org.secknight.secure_web_app.auth;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Redirects to the proper URL directory in case of
 * authentication failure (exception type).
 * /login-error : Redirects to /login with error_message that credentials were invalid (BadCredentialsException)
 * /error: In case of an IP is blocked (InternalAuthenticationServiceException, AuthenticationServiceException)
 */
@Component ("MyComponents.Auth.AuthFailureHandler")
public class AuthFailureHandler extends SimpleUrlAuthenticationFailureHandler{

    private final Map<String, String> failureUrlMap;

    public AuthFailureHandler(){
        /*
        * Map Authentication Exceptions to HTML pages
        * By default go to /login-error
        */
        failureUrlMap=new DefaultHashMap<>("/login-error");
        failureUrlMap.put("InternalAuthenticationServiceException","/error");
        failureUrlMap.put("AuthenticationServiceException","/error");
        failureUrlMap.put("BadCredentialsException","/login-error");
    }
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {

        getRedirectStrategy().sendRedirect(request, response, failureUrlMap.get(exception.getClass().getSimpleName()));
    }
}
class DefaultHashMap<K,V> extends HashMap<K,V> {
    protected V defaultValue;
    public DefaultHashMap(V defaultValue) {
        this.defaultValue = defaultValue;
    }
    @Override
    public V get(Object k) {
        return containsKey(k) ? super.get(k) : defaultValue;
    }
}