package com.example.libreoffice.util;

import java.util.Map;

public final class OfficeMime {
    private static final Map<String, String> MIME = Map.of(
            "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "doc", "application/msword",
            "xls", "application/vnd.ms-excel",
            "odt", "application/vnd.oasis.opendocument.text",
            "ods", "application/vnd.oasis.opendocument.spreadsheet",
            "pdf", "application/pdf");

    private OfficeMime() {
    }

    public static boolean supported(String ext) {
        return ext != null && MIME.containsKey(ext);
    }

    public static String of(String ext) {
        return MIME.getOrDefault(ext, "application/octet-stream");
    }

    /** word | cell | slide | pdf - giá trị documentType của ONLYOFFICE. */
    public static String documentType(String ext) {
        return switch (ext) {
            case "xlsx", "xls", "ods", "csv" -> "cell";
            case "pptx", "ppt", "odp" -> "slide";
            case "pdf" -> "pdf";
            default -> "word";
        };
    }
}
