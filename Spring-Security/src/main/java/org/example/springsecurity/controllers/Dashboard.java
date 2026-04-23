package org.example.springsecurity.controllers;

import org.example.springsecurity.aspect.Require2FA;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.example.springsecurity.enums.ESensitivityLevel.CRITICAL;

@RestController
@RequestMapping("/api/dashboard")
public class Dashboard {

    @GetMapping("/test")
    @Require2FA(level = CRITICAL)
    public String test() {
        return "Hello World";
    }
}
