package org.example.springsecurity.controllers;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "ROLES", description = "API ROLE")
@RequestMapping("/api/roles")
@PreAuthorize("hasRole('ADMIN')")
public class RoleController {
    @GetMapping("/user/card")
    public String getCards() {
        return "This Cards getCards Controller";

    }

    @DeleteMapping("/user/card")
    public String deleteCards() {
        return "This Cards deleteCards Controller";
    }

    @PutMapping("/user/card")
    public String putCards() {
        return "This Cards putCards Controller";
    }
}
