package com.example.libreoffice.service;

import com.example.libreoffice.configuration.properties.OfficeProperties;
import com.example.libreoffice.enums.DocPermission;
import com.example.libreoffice.model.CallbackTarget;
import com.example.libreoffice.model.CurrentUser;
import com.example.libreoffice.model.DocumentItem;
import com.example.libreoffice.model.OfficeDocument;
import com.example.libreoffice.payload.request.CreateDocumentRequest;
import com.example.libreoffice.payload.request.OfficeCallbackRequest;
import com.example.libreoffice.payload.response.CreateDocumentResponse;
import com.example.libreoffice.repository.IOfficeRepository;
import com.example.libreoffice.util.OfficeMime;
import io.minio.GetPresignedObjectUrlArgs;
import io.minio.Http;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OfficeServiceImpl implements IOfficeService {
    private static final String SRC_UPLOAD = "UPLOAD";
    private static final String SRC_CLOSE_SAVE = "CLOSE_SAVE";
    private static final String SRC_FORCE_SAVE = "FORCE_SAVE";

    private final IOfficeRepository officeRepository;
    private final MinioClient minio;
    private final OfficeProperties props;
    private final TransactionTemplate transactionTemplate;
    private final RestClient restClient = RestClient.create();

    // =====================================================================
    // Danh sách
    // =====================================================================

    @Override
    public void delete(String docId, CurrentUser user) {
        UUID id = parseId(docId);

        // Dùng lại query Q1: đã lọc status <> 'DELETED' và tính quyền hiệu lực
        OfficeDocument doc = officeRepository.getConfigById(id, user.id(), user.roles())
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Không tìm thấy tài liệu")
                );

        if (doc.effectivePermission() != DocPermission.OWNER) {
            log.warn("User {} ({}) cố xóa document {} không thuộc quyền sở hữu",
                    user.id(), doc.effectivePermission(), id);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Chỉ chủ sở hữu mới được xóa tài liệu");
        }

        if (officeRepository.softDelete(id, user.id()) == 0) {
            // Bị xóa bởi request khác ngay giữa lúc kiểm tra và cập nhật
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tài liệu đã bị xóa");
        }
        log.info("Xóa mềm document id={} name={} by={}", id, doc.name(), user.id());
    }

    @Override
    public List<DocumentItem> list(CurrentUser user) {
        return officeRepository.findAccessible(user.id(), user.roles());
    }

    // =====================================================================
    // Upload / Tạo mới
    // =====================================================================

    @Override
    public CreateDocumentResponse upload(MultipartFile file, CurrentUser user) {
        String original = StringUtils.getFilename(Objects.requireNonNullElse(file.getOriginalFilename(), "file"));
        String ext = StringUtils.getFilenameExtension(original);
        ext = ext == null ? "" : ext.toLowerCase();

        if (file.isEmpty() || !OfficeMime.supported(ext)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File không hợp lệ: " + original);
        }
        try {
            return store(original, ext, file.getBytes(), user);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Không đọc được file");
        }
    }

    @Override
    public CreateDocumentResponse createBlank(CreateDocumentRequest req, CurrentUser user) {
        String ext = req.type().ext();
        String name = req.name().strip();
        if (!name.toLowerCase().endsWith("." + ext)) {
            name = name + "." + ext;
        }
        try (InputStream in = new ClassPathResource("office-templates/new." + ext).getInputStream()) {
            return store(name, ext, in.readAllBytes(), user);
        } catch (IOException e) {
            log.error("Thiếu template office-templates/new.{}", ext, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Thiếu file template " + ext);
        }
    }

    /**
     * Upload MinIO trước, ghi DB sau; DB lỗi thì xóa object (bù trừ).
     */
    private CreateDocumentResponse store(String name, String ext, byte[] data, CurrentUser user) {
        UUID id = UUID.randomUUID();
        String objectKey = newObjectKey(id, ext);

        putObject(props.bucket(), objectKey, data, OfficeMime.of(ext));
        try {
            transactionTemplate.executeWithoutResult(_ -> {
                officeRepository.insertDocument(id, name, ext, OfficeMime.of(ext), data.length, props.bucket(), objectKey, user.id());
                String editorKey = officeRepository.getEditorKey(id);
                officeRepository.insertVersion(id, 1, objectKey, data.length, sha256(data), SRC_UPLOAD, editorKey, List.of(user.id()));
            });
        } catch (RuntimeException e) {
            removeObjectQuietly(props.bucket(), objectKey);
            throw e;
        }
        log.info("Tạo document id={} name={} by={}", id, name, user.id());
        return new CreateDocumentResponse(id, name, ext);
    }

    // =====================================================================
    // Config cho editor
    // =====================================================================

    @Override
    public Map<String, Object> getEditorConfig(String docId, CurrentUser user) {
        UUID id = parseId(docId);

        OfficeDocument doc = officeRepository.getConfigById(id, user.id(), user.roles())
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Không tìm thấy tài liệu")
                );

        DocPermission perm = doc.effectivePermission();
        if (perm == null) {
            log.warn("User {} không có quyền với document {}", user.id(), id);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Bạn không có quyền truy cập tài liệu này");
        }

        boolean active = "ACTIVE".equals(doc.status());
        boolean canEdit = active && perm.atLeast(DocPermission.EDIT);
        boolean canComment = active && perm.atLeast(DocPermission.COMMENT);

        Map<String, Object> document = Map.of(
                "fileType", doc.fileExt(),
                "key", doc.editorKey(),
                "title", doc.name(),
                "url", presign(doc.bucket(), doc.objectKey()),
                "permissions", Map.of(
                        "edit", canEdit,
                        "comment", canComment,
                        "download", true,
                        "print", true));

        Map<String, Object> editorConfig = Map.of(
                "mode", canEdit ? "edit" : "view",
                "callbackUrl", props.callbackBaseUrl() + "/office/callback/" + id,
                "lang", "vi",
                "user", Map.of("id", user.id(), "name", user.displayName()),
                "customization", Map.of("forcesave", true));

        log.info("Cấp config document={} version={} user={} perm={}",
                id, doc.currentVersion(), user.id(), perm);

        return Map.of(
                "documentType", OfficeMime.documentType(doc.fileExt()),
                "document", document,
                "editorConfig", editorConfig);
    }

    // =====================================================================
    // Callback từ ONLYOFFICE
    // =====================================================================

    @Override
    public int handleCallback(String docId, OfficeCallbackRequest cb) {
        UUID id;
        try {
            id = UUID.fromString(docId);
        } catch (IllegalArgumentException e) {
            log.warn("Callback với id không hợp lệ: {}", docId);
            return 0;
        }
        log.info("Callback document={} key={} status={} users={}", id, cb.key(), cb.status(), cb.users());

        return switch (cb.status()) {
            case 2 -> saveVersion(id, cb, true);      // đóng phiên, có thay đổi
            case 6 -> saveVersion(id, cb, false);     // force save
            case 3, 7 -> {
                log.error("LỖI LƯU DOCUMENT {} STATUS {}", id, cb.status());
                officeRepository.insertCallbackLog(id, cb, null, "ONLY-OFFICE save error");
                yield 0;
            }
            default -> 0; // 1: ĐANG SỬA, 4: ĐÓNG KHÔNG ĐỔI
        };
    }

    private int saveVersion(UUID id, OfficeCallbackRequest cb, boolean closeSession) {
        String source = closeSession ? SRC_CLOSE_SAVE : SRC_FORCE_SAVE;
        long start = System.nanoTime();

        try (var _ = MDC.putCloseable("docId", id.toString());
             var _ = MDC.putCloseable("key", cb.key());
             var _ = MDC.putCloseable("status", String.valueOf(cb.status()))) {

            log.info("[SAVE] BẮT ĐẦU LƯU VERSION SOURCE [{}] USERS [{}]", source, cb.users());

            // CHECK DOCUMENT CÒN TỒN TẠI HAY KHÔNG
            CallbackTarget target = officeRepository.findCallbackTarget(id).orElse(null);
            if (target == null) {
                log.warn("[SAVE] BỎ QUA: DOCUMENT KHÔNG TỒN TẠI HOẶC ĐÃ XOÁ !");
                return 0;
            }
            log.debug("[SAVE] Target ext={} bucket={} currentKey={}", target.fileExt(), target.bucket(), target.editorKey());

            // CHECK PHIÊN BẢN HIỆN TẠI
            if (!target.editorKey().equals(cb.key())) {
                log.warn("[SAVE] Bỏ qua: callback của phiên cũ (key hiện tại={})", target.editorKey());
                return 0;
            }

            // CHECK STATUS 2 ĐÃ SỬ LÝ CHƯA (ONLY-OFFICE retry)
            if (closeSession && officeRepository.closeCallbackProcessed(cb.key())) {
                log.info("[SAVE] Bỏ qua: status 2 của phiên này đã được xử lý trước đó");
                return 0;
            }

            // FORCE SAVE MÀ KHÔNG CÓ THAY ĐỔI - KHÔNG TẠO VERSION THỪA
            if (!closeSession && Boolean.TRUE.equals(cb.notmodified())) {
                log.info("[SAVE] Bỏ qua: force save nhưng tài liệu không thay đổi");
                return 0;
            }

            // TẢI FILE ĐÃ SỬA TỪ ONLY-OFFICE
            byte[] data;
            long nanoTime = System.nanoTime();
            try {
                data = download(cb.url());
                log.info("[SAVE] TẢI FILE TỪ ONLY-OFFICE OK SIZE [{}] BYTES ({} MS)", data.length, ms(nanoTime));
            } catch (Exception e) {
                log.error("[SAVE] TẢI FILE TỪ ONLY-OFFICE THẤT BẠI HOST={} → TRẢ ERROR=1 ĐỂ ONLYOFFICE GỬI LẠI", hostOf(cb.url()), e);
                return 1;
            }

            // UPLOAD LÊN MINIO (OBJECT MỚI, KHÔNG GHI ĐÈ)
            String objectKey = newObjectKey(id, target.fileExt());
            nanoTime = System.nanoTime();
            try {
                putObject(target.bucket(), objectKey, data, OfficeMime.of(target.fileExt()));
                log.info("[SAVE] UPLOAD MINIO OK OBJECT={}/{} ({} MS)", target.bucket(), objectKey, ms(nanoTime));
            } catch (RuntimeException e) {
                log.error("[SAVE] UPLOAD MINIO THẤT BẠI OBJECT={}/{} → TRẢ ERROR=1", target.bucket(), objectKey, e);
                return 1;
            }

            List<String> users = cb.users() == null ? List.of() : cb.users();
            String lastUser = users.isEmpty() ? "only-office" : users.getLast();

            // GHI DB TRONG 1 TRANSACTION
            try {
                nanoTime = System.nanoTime();
                Integer newVersion = transactionTemplate.execute(tx -> {
                    Integer v = officeRepository.saveNewVersion(id, cb.key(), objectKey, data.length, lastUser, closeSession).orElse(null);
                    if (v == null) {
                        tx.setRollbackOnly();
                        return null;
                    }
                    officeRepository.insertVersion(id, v, objectKey, data.length, sha256(data), source, cb.key(), users);
                    officeRepository.insertCallbackLog(id, cb, v, null);
                    return v;
                });

                if (newVersion == null) {
                    log.warn("[SAVE] ROLLBACK: EDITOR_KEY ĐÃ ĐỔI TRONG LÚC XỬ LÝ → XÓA OBJECT {}", objectKey);
                    removeObjectQuietly(target.bucket(), objectKey);
                    return 0;
                }

                log.info("[SAVE] ✅ LƯU THÀNH CÔNG VERSION [{}] SOURCE={} BY [{}] SIZE [{}] BYTES KEYROTATED [{}] (DB {} MS, TỔNG {} MS)",
                        newVersion, source, lastUser, data.length, closeSession, ms(nanoTime), ms(start));
                return 0;

            } catch (DuplicateKeyException e) {
                log.info("[SAVE] BỎ QUA: CALLBACK TRÙNG (2 REQUEST CÙNG LÚC) -> XÓA OBJECT {}", objectKey, e);
                removeObjectQuietly(target.bucket(), objectKey);
                return 0;
            } catch (RuntimeException e) {
                log.error("[SAVE] GHI DB THẤT BẠI → XÓA OBJECT {} VÀ TRẢ ERROR=1", objectKey, e);
                removeObjectQuietly(target.bucket(), objectKey);
                return 1;
            }
        }
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    /** Chỉ log host, không log cả URL (URL cho phép tải nội dung tài liệu). */
    private static String hostOf(String url) {
        try {
            return URI.create(url).getHost();
        } catch (Exception e) {
            log.error("[hostOf] ERROR ", e);
            return "invalid-url";
        }
    }

    /**
     * Chỉ tải từ host ONLY-OFFICE được whitelist (chống SSRF).
     */
    private byte[] download(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Callback thiếu url");
        }
        URI uri = URI.create(url);
        if (!props.allowedDownloadHosts().contains(uri.getHost())) {
            throw new SecurityException("Host không được phép: " + uri.getHost());
        }
        byte[] body = restClient.get().uri(uri).retrieve().body(byte[].class);
        if (body == null || body.length == 0) {
            throw new IllegalStateException("File tải về rỗng");
        }
        return body;
    }

    // =====================================================================
    // MinIO helpers
    // =====================================================================

    private String presign(String bucket, String objectKey) {
        try {
            return minio.getPresignedObjectUrl(GetPresignedObjectUrlArgs.builder()
                    .method(Http.Method.GET)
                    .bucket(bucket)
                    .object(objectKey)
                    .expiry((int) props.presignTtl().toSeconds())
                    .build());
        } catch (Exception e) {
            log.error("Không tạo được presigned URL {}", objectKey, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Lỗi storage");
        }
    }

    private void putObject(String bucket, String key, byte[] data, String mime) {
        try {
            minio.putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(key)
                    .stream(new ByteArrayInputStream(data), (long) data.length, -1L)
                    .contentType(mime)
                    .build());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Lỗi lưu file", e);
        }
    }

    private void removeObjectQuietly(String bucket, String key) {
        try {
            minio.removeObject(RemoveObjectArgs.builder().bucket(bucket).object(key).build());
        } catch (Exception e) {
            log.error("[SAVE] ROLLBACK: EDITOR_KEY ĐÃ ĐỔI TRONG LÚC XỬ LÝ -> XÓA OBJECT {}", key, e);
        }
    }

    /**
     * docs/{id}/{uuid}.ext - mỗi version một object, không ghi đè.
     */
    private static String newObjectKey(UUID id, String ext) {
        return "docs/%s/%s.%s".formatted(id, UUID.randomUUID(), ext);
    }

    // =====================================================================
    // Utils
    // =====================================================================

    private static UUID parseId(String id) {
        try {
            return UUID.fromString(id);
        } catch (IllegalArgumentException _) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Id tài liệu không hợp lệ");
        }
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
