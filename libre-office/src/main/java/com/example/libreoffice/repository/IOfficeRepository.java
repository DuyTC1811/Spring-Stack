package com.example.libreoffice.repository;

import com.example.libreoffice.model.CallbackTarget;
import com.example.libreoffice.model.DocumentItem;
import com.example.libreoffice.model.OfficeDocument;
import com.example.libreoffice.payload.request.OfficeCallbackRequest;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface IOfficeRepository {
    int softDelete(UUID docId, String deletedBy);

    Optional<OfficeDocument> getConfigById(UUID docId, String userId, Collection<String> roles);

    List<DocumentItem> findAccessible(String userId, Collection<String> roles);

    String getEditorKey(UUID docId);

    Optional<CallbackTarget> findCallbackTarget(UUID docId);

    boolean closeCallbackProcessed(String editorKey);

    void insertDocument(UUID id, String name, String ext, String mime, long size, String bucket, String objectKey, String ownerId);

    void insertVersion(UUID docId, int version, String objectKey, long size, String checksum, String source, String editorKey, List<String> users);

    Optional<Integer> saveNewVersion(UUID docId, String editorKey, String objectKey, long size, String updatedBy, boolean rotateKey);

    void insertCallbackLog(UUID docId, OfficeCallbackRequest cb, Integer resultVersion, String error);
}
