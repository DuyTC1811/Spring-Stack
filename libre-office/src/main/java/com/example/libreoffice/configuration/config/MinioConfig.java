package com.example.libreoffice.configuration.config;

import com.example.libreoffice.configuration.properties.MinioProperties;
import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Slf4j
@Configuration
public class MinioConfig {
    @Bean
    @Primary
    MinioClient minioClient(MinioProperties p) {
        return build(p.endpoint(), p);
    }

    @Bean("presignMinioClient")
    MinioClient presignMinioClient(MinioProperties properties) {
        return build(properties.presignEndpoint(), properties);   // không gọi mạng khi ký, nên host này không cần reachable từ backend
    }

    private MinioClient build(String endpoint, MinioProperties properties) {
        return MinioClient.builder()
                .endpoint(endpoint)
                .credentials(properties.accessKey(), properties.secretKey())
                .region(properties.region())             // set region để client không phải gọi GetBucketLocation khi presign
                .build();
    }

    @Bean
    ApplicationRunner ensureBucket(MinioClient client, MinioProperties properties) {
        return _ -> {
            if (!properties.autoCreateBucket()) {
                log.info("Bỏ qua auto-create bucket '{}'", properties.bucket());
                return;
            }
            String bucket = properties.bucket();
            if (client.bucketExists(BucketExistsArgs.builder().bucket(bucket).build())) {
                log.info("Bucket '{}' đã tồn tại", bucket);
                return;
            }
            client.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
            log.info("Đã tạo bucket '{}'", bucket);
        };
    }
}
