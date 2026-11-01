package com.example.libreoffice.enums;

public enum DocType {
    DOCX, XLSX, PPTX;

    public String ext() {
        return name().toLowerCase(); }   // DOCX → "docx"
}
