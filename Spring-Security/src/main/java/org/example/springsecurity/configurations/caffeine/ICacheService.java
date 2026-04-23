package org.example.springsecurity.configurations.caffeine;

import java.time.Duration;

public interface ICacheService {
    void putCache(String key, String value, Duration duration);

    String getCache(String key);
}
