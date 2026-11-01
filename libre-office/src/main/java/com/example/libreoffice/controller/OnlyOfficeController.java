package com.example.libreoffice.controller;

import com.example.libreoffice.configuration.config.FakeUserProvider;
import com.example.libreoffice.model.DocumentItem;
import com.example.libreoffice.payload.request.CreateDocumentRequest;
import com.example.libreoffice.payload.response.CreateDocumentResponse;
import com.example.libreoffice.service.IOfficeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/onlyoffice")
public class OnlyOfficeController {
    private final IOfficeService officeService;
    private final FakeUserProvider fakeUsers;
    /**
     * Danh sách tài liệu user được truy cập.
     */
    @GetMapping("/documents")
    public ResponseEntity<List<DocumentItem>> list(@RequestHeader(value = FakeUserProvider.HEADER, defaultValue = FakeUserProvider.DEFAULT_USER) String u) {
        List<DocumentItem> itemList = officeService.list(fakeUsers.resolve(u));
        return ResponseEntity.ok(itemList);
    }

    /**
     * Upload file có sẵn.
     */
    @PostMapping(value = "/documents/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CreateDocumentResponse> upload(
            @RequestPart("file") MultipartFile file,
            @RequestHeader(value = FakeUserProvider.HEADER, defaultValue = FakeUserProvider.DEFAULT_USER) String u) {
        CreateDocumentResponse upload = officeService.upload(file, fakeUsers.resolve(u));
        return ResponseEntity.status(HttpStatus.CREATED).body(upload);
    }

    /**
     * Tạo tài liệu trắng từ template.
     */
    @PostMapping("/documents")
    public ResponseEntity<CreateDocumentResponse> create(
            /*@Valid*/ @RequestBody CreateDocumentRequest req,
                       @RequestHeader(value = FakeUserProvider.HEADER, defaultValue = FakeUserProvider.DEFAULT_USER) String u) {
        CreateDocumentResponse created = officeService.createBlank(req, fakeUsers.resolve(u));
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * Config cho <document-editor>.
     */
    @GetMapping("/{id}/config")
    public ResponseEntity<Map<String, Object>> config(
            @PathVariable String id,
            @RequestHeader(value = FakeUserProvider.HEADER, defaultValue = FakeUserProvider.DEFAULT_USER) String u) {
        Map<String, Object> editorConfig = officeService.getEditorConfig(id, fakeUsers.resolve(u));
        return ResponseEntity.ok(editorConfig);
    }

    @DeleteMapping("/documents/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id, @RequestHeader(value = FakeUserProvider.HEADER, defaultValue = FakeUserProvider.DEFAULT_USER) String u) {
        officeService.delete(id, fakeUsers.resolve(u));
        return ResponseEntity.noContent().build();
    }
}
