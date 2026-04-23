package org.example.springsecurity.configurations.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class CacheServiceImpl implements ICacheService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CacheServiceImpl.class);
    private final Cache<String, CacheValueWrapper<String>> cache;

    @Override
    public void putCache(String key, String value, Duration duration) {
        CacheValueWrapper<String> cacheValue = new CacheValueWrapper<>(value, duration);
        cache.put(key, cacheValue);
        LOGGER.debug("[ PUT CACHE ] key={} ttl={}m", key, duration);
    }

    @Override
    public String getCache(String key) {
        CacheValueWrapper<String> cacheValue = cache.getIfPresent(key);

        if (cacheValue == null) {
            return "";
        }

        if (cacheValue.isExpired()) {
            cache.invalidate(key);
            return "";
        }

        return cacheValue.value();
    }
}
