package com.example.kafkaconsumer.configuration;

import com.clickhouse.client.api.Client;
import com.example.kafkaconsumer.configuration.properties.ClickHouseProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.temporal.ChronoUnit;

@Configuration
public class ClickHouseConfig {
    @Bean(destroyMethod = "close")
    public Client clickHouseClient(ClickHouseProperties props) {
        Client.Builder builder = new Client.Builder()
                .addEndpoint(props.getEndpoint())
                .setDefaultDatabase(props.getDatabase())
                .setUsername(props.getUsername())
                .setPassword(props.getPassword())
                .setConnectTimeout(props.getConnectTimeout(), ChronoUnit.MILLIS)
                .setSocketTimeout(props.getSocketTimeout(), ChronoUnit.MILLIS)
                .setMaxConnections(props.getMaxConnections())
                .compressServerResponse(props.isCompress())
                .setClientName("my-spring-app");
        return builder.build();
    }
}
