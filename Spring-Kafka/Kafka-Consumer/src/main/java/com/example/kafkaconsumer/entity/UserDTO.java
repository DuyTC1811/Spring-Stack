package com.example.kafkaconsumer.entity;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private Boolean isActive;       // boolean từ JSON
    private Long createdAt;         // epoch microseconds từ Kafka
}
