package com.example.libreoffice.model;

import java.util.List;

public record CurrentUser (String id, String displayName, List<String> roles) {
}
