package org.secknight.secure_web_app.audit;

import java.util.HashMap;
import java.util.Map;
import org.springframework.aop.framework.ReflectiveMethodInvocation;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.security.AbstractAuthorizationAuditListener;
import org.springframework.security.access.event.*;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Logs an Authorization Failure Attempt
 * The event is published and handled by
 * the AuditManager
 * @see AuditManager
 */
@Component ("MyComponents.Audit.AuthorizationListener")
public class AuthorizationListener extends AbstractAuthorizationAuditListener {
 
    @Override
    public void onApplicationEvent(AbstractAuthorizationEvent event) {
        if (event instanceof AuthorizationFailureEvent) {
            Map<String, Object> data = new HashMap<>();
            if (event.getSource() instanceof FilterInvocation)
                data.put("url_source", event.getSource());
            else if (event.getSource() instanceof ReflectiveMethodInvocation)
                data.put("method_source", event.getSource());
            else{
                data.put("unknown_source", event.getSource().getClass().getName());
            }
            data.put("config", ((AuthorizationFailureEvent) event).getConfigAttributes());
            data.put("authorities", ((AuthorizationFailureEvent) event).getAuthentication().getAuthorities());
            WebAuthenticationDetails details = (WebAuthenticationDetails) ((AuthorizationFailureEvent) event).getAuthentication().getDetails();
            if (details!=null){
                data.put("ip_address", details.getRemoteAddress());
                data.put("session_id", details.getSessionId());
            }
            publish(new AuditEvent(((AuthorizationFailureEvent) event).getAuthentication().getName(),"AUTHORIZATION_FAILURE", data));
        }
    }
}