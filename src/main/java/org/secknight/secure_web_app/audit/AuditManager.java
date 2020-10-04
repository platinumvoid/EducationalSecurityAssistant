package org.secknight.secure_web_app.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.ReflectiveMethodInvocation;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import java.util.Collection;
import java.util.Map;

/**
 * Auditing refers to the logging of events that
 * have security significance, such as login/logout,
 * an attempt to perform a privileged action, a
 * modification of an important financial record, etc.
 */
@Component ("MyComponents.Audit.AuditManager")
public class AuditManager {

    private static final Logger LOG = LoggerFactory.getLogger(AuditManager.class);

    /**
     * Logs all events published throughout the whole application
     * In the case of Authorization Request we monitor access to the
     * Admin Page (Publisher located in AdminUI) as it is vital
     * to know if someone maliciously accessed the site.
     * @see org.secknight.secure_web_app.controllers.AdminUI
     */
    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        AuditEvent auditEvent = auditApplicationEvent.getAuditEvent();
        StringBuilder message=new StringBuilder();
        message.append("\nUser: ").append(auditEvent.getPrincipal()).append(" - ").append(auditEvent.getType()).append("\n")
                .append("-------------------------------").append("\n");
        getDetails(auditEvent.getData(),  message);

        switch (auditEvent.getType()) {
            case "AUTHORIZATION_REQUEST" -> {
                message.append("\tRequest URL: ").append(auditEvent.getData().get("url_source")).append("\n");
                getAuthorities(auditEvent.getData(), message);
                LOG.info(message.toString());
            }
            case "AUTHORIZATION_FAILURE" -> {
                if (auditEvent.getData().get("url_source") != null) {
                    FilterInvocation source = (FilterInvocation) auditEvent.getData().get("url_source");
                    message.append("\tRequest URL: ").append(source.getRequestUrl()).append("\n");
                } else if (auditEvent.getData().get("method_source") != null) {
                    ReflectiveMethodInvocation source = (ReflectiveMethodInvocation) auditEvent.getData().get("method_source");
                    message.append("\tRequest Method: ").append(source.getMethod().getName()).append("\n");
                } else if (auditEvent.getData().get("unknown_source") != null) {
                    message.append("\tUnknown Request: ").append(auditEvent.getData().get("unknown_source").getClass().getName()).append("\n");
                }
                getAuthorities(auditEvent.getData(), message);
                getConfigurations(auditEvent.getData(), message);
                LOG.warn(message.toString());
            }
            case "SWITCH_USER" -> {
                message.append("\tTarget User: ").append(auditEvent.getData().get("target_user")).append("\n");
                getAuthorities(auditEvent.getData(), message);
                LOG.info(message.toString());
            }
            case "AUTHENTICATION_SUCCESS", "LOGOUT_SUCCESS" -> {
                getAuthorities(auditEvent.getData(), message);
                LOG.info(message.toString());
            }
            case "AUTHENTICATION_FAILURE_BAD_CREDENTIALS", "BLOCKED_IP" -> LOG.warn(message.toString());
        }
    }

    /*HELPER FUNCTIONS*/

    private void getDetails(Map<String,Object> data, StringBuilder message) {
        message.append("\tRemote IP address: ").append(data.get("ip_address")).append("\n");
        message.append("\tSession Id: ").append(data.get("session_id")).append("\n");
    }

    private void getAuthorities(Map<String,Object> data, StringBuilder message) {
        if (data.get("authorities") instanceof Collection){
            Collection<?> grantedAuthorities=(Collection<?>) data.get("authorities");
            if (grantedAuthorities!=null && grantedAuthorities.size()>0){
                message.append("\tAuthorities: ");
                for (Object grantedAuthority : grantedAuthorities) {
                    if (grantedAuthority instanceof  GrantedAuthority)
                        message.append(((GrantedAuthority)grantedAuthority).getAuthority()).append(", ");
                }
                message.append("\n");
            }
        }
    }

    private void getConfigurations(Map<String,Object> data, StringBuilder message) {
        if (data.get("config") instanceof Collection){
            Collection<?> configAttributes=(Collection<?>) data.get("config");
            if (configAttributes!=null && configAttributes.size()>0){
                message.append("\tConfigurations: \n");
                for (Object configAttribute : configAttributes) {
                    if (configAttribute instanceof ConfigAttribute)
                        message.append("\t\t").append(((ConfigAttribute)configAttribute).getAttribute()).append("\n");
                }
            }
        }
    }
}