package org.example.springsecurity.aspect;

import lombok.RequiredArgsConstructor;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.example.springsecurity.configurations.caffeine.ICacheService;
import org.example.springsecurity.configurations.jwt.JwtUtil;
import org.example.springsecurity.configurations.properties.SecurityProperties;
import org.example.springsecurity.configurations.security.UserInfo;
import org.example.springsecurity.exceptions.BaseException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
@RequiredArgsConstructor
public class TwoFactorAspect {
    private final JwtUtil jwtUtil;
    private final SecurityProperties securityProperties;
    private final ICacheService cacheService;
    private static final String KEY_PREFIX = "2fa:stepup:%s:%s";

    @Before("@within(require2FA) || @annotation(require2FA)")
    public void check(JoinPoint jp, Require2FA require2FA) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("Not authenticated");
        }

        UserInfo userInfo = jwtUtil.usernameByContext();
        String token = jwtUtil.tokenContext();
        String jti = jwtUtil.extractJti(token, securityProperties.getAccessSecret());
        String key = String.format(KEY_PREFIX, userInfo.getUsername(), jti);

        String verified = cacheService.getCache(key);
        if (verified.isBlank()) {
            throw new BaseException(403, "2FA verification required. Please verify at /api/2fa/verify-step-up");
        }
    }
}
