package com.example.libreoffice.repository;

import com.example.libreoffice.model.CallbackTarget;
import com.example.libreoffice.model.DocumentItem;
import com.example.libreoffice.model.OfficeDocument;
import com.example.libreoffice.payload.request.OfficeCallbackRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Types;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@RequiredArgsConstructor
@Slf4j
@Repository
@Transactional
public class OfficeRepositoryImpl implements IOfficeRepository {
    private final JdbcClient jdbcClient;

    private static final String SQL_GET_CONFIG = """
            SELECT d.id, d.name, d.file_ext, d.bucket, d.object_key,
                   d.current_version, d.editor_key, d.status,
                   CASE WHEN d.owner_id = :userId THEN CAST('OWNER' AS doc_permission)
                        ELSE MAX(p.permission) END AS effective_permission
            FROM documents d
            LEFT JOIN document_permissions p
                   ON p.document_id = d.id
                  AND (p.expires_at IS NULL OR p.expires_at > now())
                  AND ( (p.principal_type = 'USER' AND p.principal_id = :userId)
                     OR (p.principal_type = 'ROLE' AND p.principal_id = ANY(CAST(:roles AS varchar[]))) )
            WHERE d.id = :docId
              AND d.status <> 'DELETED'
            GROUP BY d.id
            """;

    private static final String SQL_FIND_ACCESSIBLE = """
            SELECT d.id, d.name, d.file_ext, d.current_version, d.updated_at
            FROM documents d
            WHERE d.status <> 'DELETED'
              AND ( d.owner_id = :userId
                 OR EXISTS (SELECT 1 FROM document_permissions p
                            WHERE p.document_id = d.id
                              AND (p.expires_at IS NULL OR p.expires_at > now())
                              AND ( (p.principal_type = 'USER' AND p.principal_id = :userId)
                                 OR (p.principal_type = 'ROLE' AND p.principal_id = ANY(CAST(:roles AS varchar[]))) )) )
            ORDER BY d.updated_at DESC
            LIMIT 50
            """;

    private static final String SQL_INSERT_DOCUMENT = """
            INSERT INTO documents (id, name, file_ext, mime_type, size_bytes, bucket, object_key, owner_id, updated_by)
            VALUES (:id, :name, :ext, :mime, :size, :bucket, :objectKey, :ownerId, :ownerId)
            """;

    private static final String SQL_INSERT_VERSION = """
            INSERT INTO document_versions
                   (document_id, version, object_key, size_bytes, checksum, source, editor_key, changed_by)
            VALUES (:docId, :version, :objectKey, :size, :checksum,
                    CAST(:source AS version_source), :editorKey, CAST(:users AS varchar[]))
            """;

    private static final String SQL_SAVE_NEW_VERSION = """
            UPDATE documents
               SET current_version = current_version + 1,
                   object_key      = :objectKey,
                   size_bytes      = :size,
                   updated_at      = now(),
                   updated_by      = :updatedBy,
                   editor_key      = CASE WHEN :rotateKey
                                          THEN replace(gen_random_uuid()::text, '-', '')
                                          ELSE editor_key END
             WHERE id = :docId
               AND editor_key = :editorKey
               AND status = 'ACTIVE'
            RETURNING current_version
            """;

    private static final String SQL_INSERT_CALLBACK_LOG = """
            INSERT INTO office_callback_log (
                document_id,
                editor_key,
                status,
                file_url,
                payload,
                result_version,
                error
            )
            VALUES (
                :docId,
                :editorKey,
                CAST(:status AS smallint),
                :url,
                jsonb_build_object(
                    'users',         CAST(:users AS varchar[]),
                    'forcesavetype', CAST(:forceSaveType AS int)
                ),
                :resultVersion,
                :error
            )
            """;



    private static final String SQL_SOFT_DELETE = """
        UPDATE documents
           SET status     = 'DELETED',
               updated_at = now(),
               updated_by = :deletedBy
         WHERE id = :docId
           AND status <> 'DELETED'
        """;

    @Override
    public int softDelete(UUID docId, String deletedBy) {
        return jdbcClient.sql(SQL_SOFT_DELETE)
                .param("docId", docId)
                .param("deletedBy", deletedBy)
                .update();
    }

    // =====================================================================
    // READ
    // =====================================================================
    @Override
    public Optional<OfficeDocument> getConfigById(UUID docId, String userId, Collection<String> roles) {
        return jdbcClient.sql(SQL_GET_CONFIG)
                .param("docId", docId)
                .param("userId", userId)
                .param("roles", toArray(roles))
                .query(OfficeDocument.class)        // map cột snake_case → field camelCase
                .optional();
    }

    @Override
    public List<DocumentItem> findAccessible(String userId, Collection<String> roles) {
        return jdbcClient.sql(SQL_FIND_ACCESSIBLE)
                .param("userId", userId)
                .param("roles", toArray(roles))
                .query(DocumentItem.class)
                .list();
    }

    @Override
    public String getEditorKey(UUID docId) {
        return jdbcClient.sql("SELECT editor_key FROM documents WHERE id = :id")
                .param("id", docId)
                .query(String.class)
                .single();
    }

    @Override
    public Optional<CallbackTarget> findCallbackTarget(UUID docId) {
        return jdbcClient.sql("""
                        SELECT file_ext, bucket, editor_key
                        FROM documents
                        WHERE id = :id AND status <> 'DELETED'
                        """)
                .param("id", docId)
                .query(CallbackTarget.class)
                .optional();
    }

    @Override
    public boolean closeCallbackProcessed(String editorKey) {
        return jdbcClient.sql("""
                        SELECT EXISTS (SELECT 1 FROM office_callback_log
                                       WHERE editor_key = :key AND status = 2)
                        """)
                .param("key", editorKey)
                .query(Boolean.class)
                .single();
    }

    // =====================================================================
    // INSERT
    // =====================================================================

    @Override
    public void insertDocument(UUID id, String name, String ext, String mime, long size, String bucket, String objectKey, String ownerId) {
        jdbcClient.sql(SQL_INSERT_DOCUMENT)
                .param("id", id)
                .param("name", name)
                .param("ext", ext)
                .param("mime", mime)
                .param("size", size)
                .param("bucket", bucket)
                .param("objectKey", objectKey)
                .param("ownerId", ownerId)
                .update();
    }

    @Override
    public void insertVersion(UUID docId, int version, String objectKey, long size, String checksum, String source, String editorKey, List<String> users) {
        jdbcClient.sql(SQL_INSERT_VERSION)
                .param("docId", docId)
                .param("version", version)
                .param("objectKey", objectKey)
                .param("size", size)
                .param("checksum", checksum)
                .param("source", source)
                .param("editorKey", editorKey)
                .param("users", toArray(users))
                .update();
    }

    @Override
    public Optional<Integer> saveNewVersion(UUID docId, String editorKey, String objectKey, long size, String updatedBy, boolean rotateKey) {
        return jdbcClient.sql(SQL_SAVE_NEW_VERSION)
                .param("objectKey", objectKey)
                .param("size", size)
                .param("updatedBy", updatedBy)
                .param("rotateKey", rotateKey)
                .param("docId", docId)
                .param("editorKey", editorKey)
                .query(Integer.class) // UPDATE ... RETURNING
                .optional();
    }

    @Override
    public void insertCallbackLog(UUID docId, OfficeCallbackRequest cb, Integer resultVersion, String error) {
        jdbcClient.sql(SQL_INSERT_CALLBACK_LOG)
                .param("docId", docId)
                .param("editorKey", cb.key())
                .param("status", cb.status())
                .param("url", cb.url())
                .param("users", toArray(cb.users()))
                .param("forceSaveType", cb.forcesavetype(), Types.INTEGER)
                .param("resultVersion", resultVersion, Types.INTEGER)
                .param("error", error, Types.VARCHAR)
                .update();
    }

    private static String[] toArray(Collection<String> values) {
        return values == null ? new String[0] : values.toArray(String[]::new);
    }
}
