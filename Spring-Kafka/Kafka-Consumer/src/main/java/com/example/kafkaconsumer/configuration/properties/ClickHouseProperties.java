package com.example.kafkaconsumer.configuration.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "clickhouse")
public class ClickHouseProperties {
    private String endpoint;
    private String database;
    private String username;
    private String password;
    private long connectTimeout = 30000;
    private long socketTimeout = 60000;
    private int maxConnections = 10;
    private boolean compress = true;
}
