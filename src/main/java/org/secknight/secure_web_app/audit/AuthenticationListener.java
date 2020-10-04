package org.secknight.secure_web_app.audit;

import org.secknight.secure_web_app.auth.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthenticationAuditListener;
import org.springframework.security.authentication.event.*;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.stereotype.Component;
import java.util.HashMap;
import java.util.Map;

/**
 * Logs all important Authentication Events
 * In case of Authentication Failure increases the login
 * attempts made by a single IP Address in order to block
 * it if reaches the maximum attempt threshold
 * In case of Authentication Success invalidates
 * all previous failed attempts for the current IP Address
 * Also monitors all states of a current user (Authenticated,
 * Log Out or Switch to Another User - Only Admin)
 * All events are published and handled by
 * the AuditManager
 * @see LoginAttemptService
 * @see AuditManager
 */
@Component ("MyComponents.Audit.AuthenticationListener")
public class AuthenticationListener extends AbstractAuthenticationAuditListener {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
        Map<String, Object> data = new HashMap<>();
        WebAuthenticationDetails details = (WebAuthenticationDetails) event.getAuthentication().getDetails();
        data.put("ip_address", details.getRemoteAddress());
        data.put("session_id", details.getSessionId());
        String principal=event.getAuthentication().getName();

        if (event instanceof AbstractAuthenticationFailureEvent){
            if (event instanceof AuthenticationFailureBadCredentialsEvent){
                loginAttemptService.loginFailed(details.getRemoteAddress());
                publish(new AuditEvent(principal,"AUTHENTICATION_FAILURE_BAD_CREDENTIALS", data));
            }else if (event instanceof AuthenticationFailureServiceExceptionEvent)
                publish(new AuditEvent(principal,"BLOCKED_IP", data));
        }else{
            data.put("authorities", event.getAuthentication().getAuthorities());
            if (event instanceof AuthenticationSuccessEvent){
                loginAttemptService.loginSucceeded(details.getRemoteAddress());
                publish(new AuditEvent(principal,"AUTHENTICATION_SUCCESS", data));
            }else if (event instanceof AuthenticationSwitchUserEvent){
                data.put("target_user",  ((AuthenticationSwitchUserEvent)event).getTargetUser().getUsername());
                publish(new AuditEvent(principal,"SWITCH_USER", data));
            }else if (event instanceof LogoutSuccessEvent)
                publish(new AuditEvent(principal,"LOGOUT_SUCCESS", data));
        }
    }
}
