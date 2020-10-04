package org.secknight.secure_web_app.auth;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.springframework.stereotype.Service;

import javax.annotation.ParametersAreNonnullByDefault;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Service("MyServices.LoginAttemptService")
public class LoginAttemptService {

    /**
     * Select the maximum attempts an IP Address
     * has before it gets blocked
     */
    private static final int MAX_ATTEMPTS =20;

    private final LoadingCache<String, AtomicInteger> IPAddressCache;

    public LoginAttemptService() {
        IPAddressCache = CacheBuilder
                .newBuilder()
                /*
                 * Select the duration of an IP to remain
                 * blocked
                 */
                .expireAfterWrite(1, TimeUnit.DAYS)
                .build(new CacheLoader<>() {
                    @Override
                    @ParametersAreNonnullByDefault
                    public AtomicInteger load( String key) {
                        return new AtomicInteger(0);
                    }
                });
    }

    /**
     * Remove all attempts for the given IP Address
     * since Authentication was successful
     * @param key IP Address
     */
    public void loginSucceeded(String key) {
        IPAddressCache.invalidate(key);
    }

    /**
     * Increment attempts for the given IP Address
     * @param key IP address
     */
    public void loginFailed(String key) {
        try {
            IPAddressCache.get(key).getAndIncrement();
        } catch (ExecutionException e) {
            throw new RuntimeException("LoginAttemptService: " + e, e);
        }
    }

    /**
     * Block an IP address if it reached its maximum
     * attempts
     * @param key IP address
     * @return True if Blocked, otherwise False
     */
    public boolean isIPBlocked(String key) {
        try {
            return IPAddressCache.get(key).get() >= MAX_ATTEMPTS;
        } catch (ExecutionException e) {
            return false;
        }
    }
}
