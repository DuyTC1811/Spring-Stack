package com.example.libreoffice.payload.request;

import com.example.libreoffice.enums.DocType;

public record CreateDocumentRequest (String name, DocType type) {
}
