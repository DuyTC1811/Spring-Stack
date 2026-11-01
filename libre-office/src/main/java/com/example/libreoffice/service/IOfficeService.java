package com.example.libreoffice.service;

import com.example.libreoffice.model.CurrentUser;
import com.example.libreoffice.model.DocumentItem;
import com.example.libreoffice.payload.request.CreateDocumentRequest;
import com.example.libreoffice.payload.request.OfficeCallbackRequest;
import com.example.libreoffice.payload.response.CreateDocumentResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

public interface IOfficeService {
    /**
     * DELETE /api/onlyoffice/documents/{id}
     */
    void delete(String docId, CurrentUser user);

    /**
     * GET /api/office/documents
     */
    List<DocumentItem> list(CurrentUser user);

    /**
     * POST /api/office/documents/upload
     */
    CreateDocumentResponse upload(MultipartFile file, CurrentUser user);

    /**
     * POST /api/office/documents
     */
    CreateDocumentResponse createBlank(CreateDocumentRequest req, CurrentUser user);

    /**
     * GET /api/office/{id}/config
     */
    Map<String, Object> getEditorConfig(String docId, CurrentUser user);

    /**
     * POST /office/callback/{id}
     *
     * @return 0 = OK, 1 = lỗi (ONLYOFFICE sẽ gửi lại)
     */
    int handleCallback(String docId, OfficeCallbackRequest callback);
}
