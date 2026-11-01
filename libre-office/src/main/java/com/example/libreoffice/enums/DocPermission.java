package com.example.libreoffice.enums;

public enum DocPermission {
    VIEW,
    COMMENT,
    EDIT,
    OWNER;

    public boolean atLeast(DocPermission other) {
        return this.compareTo(other) >= 0;
    }
}
