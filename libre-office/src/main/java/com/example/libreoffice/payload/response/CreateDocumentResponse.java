package com.example.libreoffice.payload.response;

import java.util.UUID;

public record CreateDocumentResponse(UUID id, String name, String fileExt) {

}
