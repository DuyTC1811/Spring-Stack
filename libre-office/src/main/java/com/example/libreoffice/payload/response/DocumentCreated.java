package com.example.libreoffice.payload.response;

import java.util.UUID;

public record DocumentCreated(UUID id, String name, String fileExt) {

}
