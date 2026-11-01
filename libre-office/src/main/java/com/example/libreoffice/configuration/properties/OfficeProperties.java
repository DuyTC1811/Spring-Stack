package com.example.libreoffice.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "only-office")
public record OfficeProperties(
        String callbackBaseUrl,          // URL mà container ONLY-OFFICE gọi được
        String bucket,          // URL mà container ONLY-OFFICE gọi được
        Duration presignTtl,
        List<String> allowedDownloadHosts
) {
}
