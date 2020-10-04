package org.secknight.secure_web_app.security;

import org.secknight.secure_web_app.auth.LoginAttemptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Order(1)
public class LoginAttemptFilter implements Filter {

    private final LoginAttemptService loginAttemptService;

    private static final Logger LOG = LoggerFactory.getLogger(LoginAttemptFilter.class);

    public LoginAttemptFilter(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void doFilter (ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String IPAddress;
        HttpServletRequest req = (HttpServletRequest) request;
        String xfHeader = req.getHeader("X-Forwarded-For");
        if (xfHeader == null) IPAddress= request.getRemoteAddr();
        else IPAddress= xfHeader.split(",")[0];

        if (!loginAttemptService.isIPBlocked(IPAddress)) {
            chain.doFilter(request, response);
        }else{
            LOG.warn("IP "+IPAddress+" has been blocked");
            ((HttpServletResponse)response).sendError(403);
        }
    }
}