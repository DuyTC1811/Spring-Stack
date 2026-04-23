package org.example.springsecurity.configurations.caffeine;

import java.time.Duration;
import java.time.Instant;

public record CacheValueWrapper<T>(T value, Instant expirationTime) {
    public CacheValueWrapper(T value, Duration duration) {
        this(value, Instant.now().plus(duration));
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expirationTime);
    }

    public Duration remainingTtl() {
        Duration remaining = Duration.between(Instant.now(), expirationTime);
        return remaining.isNegative() ? Duration.ZERO : remaining;
    }
}
