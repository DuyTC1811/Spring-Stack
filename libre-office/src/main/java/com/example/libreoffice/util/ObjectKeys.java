package com.example.libreoffice.util;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public final class ObjectKeys {
    private static final String ROOT = "documents";
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private ObjectKeys() {
    }

    /**
     * Thư mục của 1 tài liệu: documents/{docId}/
     */
    public static String folder(UUID docId) {
        return "%s/%s/".formatted(ROOT, docId);
    }

    /**
     * Bản gốc khi upload / tạo mới: documents/{docId}/original.docx
     */
    public static String original(UUID docId, String ext) {
        return folder(docId) + "original." + ext;
    }

    /**
     * Bản lưu từ ONLYOFFICE: documents/{docId}/versions/20261101-221005_force_9c1e4a.docx
     */
    public static String version(UUID docId, SaveSource source, String ext) {
        return "%sversions/%s_%s_%s.%s".formatted(
                folder(docId),
                ZonedDateTime.now(ZONE).format(TS),
                source.tag(),
                UUID.randomUUID().toString().substring(0, 6),
                ext);
    }

    public enum SaveSource {
        FORCE_SAVE("force"),
        CLOSE_SAVE("close");

        private final String tag;

        SaveSource(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }
}
