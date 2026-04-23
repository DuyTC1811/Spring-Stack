package org.example.springsecurity.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ESensitivityLevel {
    CRITICAL(2),
    HIGH(5),
    NORMAL(15),
    LOW(30);
    private final int minutes;
}
