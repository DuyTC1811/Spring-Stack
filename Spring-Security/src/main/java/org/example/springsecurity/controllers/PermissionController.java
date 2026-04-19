package org.example.springsecurity.controllers;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "PERMISSIONS", description = "API PHÂN QUYỀN")
@RequestMapping("/api/permissions")
@PreAuthorize("hasRole('ADMIN')")
public class PermissionController {
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
