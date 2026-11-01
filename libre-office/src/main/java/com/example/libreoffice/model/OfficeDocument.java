package com.example.libreoffice.model;

import com.example.libreoffice.enums.DocPermission;

import java.util.UUID;

public record OfficeDocument(
        UUID id,
        String name,
        String fileExt,
        String bucket,
        String objectKey,
        int currentVersion,
        String editorKey,
        String status,
        DocPermission effectivePermission    // null = không có quyền
) {
}
