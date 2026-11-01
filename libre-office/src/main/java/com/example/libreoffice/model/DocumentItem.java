package com.example.libreoffice.model;

import java.time.OffsetDateTime;
import java.util.UUID;

public record DocumentItem(
        UUID id,
        String name,
        String fileExt,
        int currentVersion,
        OffsetDateTime updatedAt
) {
}
