package com.example.libreoffice.controller;

import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/onlyoffice")
public class OnlyOfficeController {
    @GetMapping("/api/office/{id}/config")
    public Map<String, Object> config(@PathVariable String id, Authentication auth) {

//        return Map.of(
//                "documentType", docType(m.extension()),
//                "document", Map.of(
//                        "fileType", m.extension(),
//                        "key", id + "_" + m.version(),
//                        "title", m.name(),
//                        "url", api + "/office/files/" + id),
//                "editorConfig", Map.of(
//                        "callbackUrl", api + "/office/callback/" + id,
//                        "lang", "vi",
//                        "user", Map.of("id", user.id(), "name", user.displayName()),
//                        "customization", Map.of("forcesave", true)));
//        // không còn trường "token"
    }

    @GetMapping("/office/files/{id}")
    public ResponseEntity<byte[]> file(@PathVariable String id) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(storage.read(id));
    }

    @PostMapping("/office/callback/{id}")
    public Map<String, Integer> callback(@PathVariable String id, @RequestBody Map<String, Object> body) {
        int status = ((Number) body.get("status")).intValue();
        if (status == 2 || status == 6) {
            byte[] data = RestClient.create().get().uri((String) body.get("url")).retrieve().body(byte[].class);
            storage.write(id, data);
        }
        return Map.of("error", 0);
    }

    private String docType(String ext) {
        return switch (ext) {
            case "xlsx", "xls", "csv", "ods" -> "cell";
            case "pptx", "ppt", "odp" -> "slide";
            default -> "word";
        };
    }
}
