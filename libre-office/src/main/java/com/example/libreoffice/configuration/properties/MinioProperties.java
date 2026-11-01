package com.example.libreoffice.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "minio")
public record MinioProperties(
        String endpoint,
        String presignEndpoint,
        String accessKey,
        String secretKey,
        String region,
        String bucket,
        boolean autoCreateBucket
) {
}
