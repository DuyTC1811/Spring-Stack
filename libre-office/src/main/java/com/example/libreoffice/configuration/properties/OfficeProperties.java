package com.example.libreoffice.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "only-office")
public record OfficeProperties(
        String callbackBaseUrl,
        String bucket,
        Duration presignTtl,
        List<String> allowedDownloadHosts
) {
}
