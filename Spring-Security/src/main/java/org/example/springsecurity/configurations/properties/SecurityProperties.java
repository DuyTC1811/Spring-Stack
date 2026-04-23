package org.example.springsecurity.configurations.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Component
@ConfigurationProperties(prefix = "spring.jwt")
public class SecurityProperties {
    private String accessSecret;
    private long accessTime;
    private String refreshSecret;
    private long refreshTime;
    private String verifiedSecret;
    private long verifiedTime;
}
