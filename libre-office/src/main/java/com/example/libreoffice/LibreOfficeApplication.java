package com.example.libreoffice;

import com.example.libreoffice.configuration.properties.MinioProperties;
import com.example.libreoffice.configuration.properties.OfficeProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({OfficeProperties.class, MinioProperties.class})
public class LibreOfficeApplication {

    static void main(String[] args) {
        SpringApplication.run(LibreOfficeApplication.class, args);
    }

}
