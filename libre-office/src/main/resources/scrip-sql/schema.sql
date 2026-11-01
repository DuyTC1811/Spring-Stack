-- =====================================================================
-- ONLYOFFICE document metadata schema - PostgreSQL
-- =====================================================================

CREATE TYPE doc_status AS ENUM ('ACTIVE', 'LOCKED', 'DELETED');
-- Thứ tự khai báo = thứ tự so sánh => MAX(permission) ra quyền cao nhất
CREATE TYPE doc_permission AS ENUM ('VIEW', 'COMMENT', 'EDIT', 'OWNER');
CREATE TYPE principal_type AS ENUM ('USER', 'ROLE');
CREATE TYPE version_source AS ENUM ('UPLOAD', 'CLOSE_SAVE', 'FORCE_SAVE', 'RESTORE');

-- ---------------------------------------------------------------------
-- 1. Tài liệu (metadata + trạng thái hiện tại)
-- ---------------------------------------------------------------------
CREATE TABLE documents
(
    id              UUID PRIMARY KEY      DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    file_ext        VARCHAR(10)  NOT NULL, -- docx, xlsx, pptx
    mime_type       VARCHAR(100) NOT NULL,
    size_bytes      BIGINT       NOT NULL,
    bucket          VARCHAR(63)  NOT NULL DEFAULT 'docs',
    object_key      VARCHAR(512) NOT NULL, -- object của version hiện tại
    current_version INT          NOT NULL DEFAULT 1,
    -- document.key gửi cho ONLYOFFICE. CHỈ đổi khi phiên sửa kết thúc (status 2),
    -- KHÔNG đổi khi force save, nếu không người mở sau sẽ vào phiên khác.
    editor_key      VARCHAR(128) NOT NULL DEFAULT replace(gen_random_uuid()::text, '-', ''),
    owner_id        VARCHAR(64)  NOT NULL,
    status          doc_status   NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_by      VARCHAR(64),
    CONSTRAINT ck_documents_ext CHECK (file_ext IN
                                       ('docx', 'doc', 'odt', 'xlsx', 'xls', 'ods', 'csv', 'pptx', 'ppt', 'odp', 'pdf'))
);

CREATE UNIQUE INDEX ux_documents_editor_key ON documents (editor_key);
CREATE INDEX ix_documents_owner ON documents (owner_id) WHERE status <> 'DELETED';

-- ---------------------------------------------------------------------
-- 2. Lịch sử version (mỗi lần lưu = 1 dòng, file nằm trên MinIO)
-- ---------------------------------------------------------------------
CREATE TABLE document_versions
(
    id          BIGSERIAL PRIMARY KEY,
    document_id UUID           NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    version     INT            NOT NULL,
    object_key  VARCHAR(512)   NOT NULL,              -- docs/{id}/v{version}.docx
    size_bytes  BIGINT         NOT NULL,
    checksum    CHAR(64),                             -- SHA-256 hex
    source      version_source NOT NULL,
    editor_key  VARCHAR(128)   NOT NULL,              -- phiên ONLYOFFICE tạo ra version này
    changed_by  VARCHAR(64)[]  NOT NULL DEFAULT '{}', -- users[] từ callback
    created_at  TIMESTAMPTZ    NOT NULL DEFAULT now(),
    CONSTRAINT ux_document_versions UNIQUE (document_id, version)
);

-- ---------------------------------------------------------------------
-- 3. Phân quyền theo user hoặc role (VD role từ Keycloak)
-- ---------------------------------------------------------------------
CREATE TABLE document_permissions
(
    document_id    UUID           NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    principal_type principal_type NOT NULL,
    principal_id   VARCHAR(64)    NOT NULL, -- userId hoặc tên role
    permission     doc_permission NOT NULL,
    granted_by     VARCHAR(64)    NOT NULL,
    granted_at     TIMESTAMPTZ    NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,             -- NULL = vĩnh viễn
    PRIMARY KEY (document_id, principal_type, principal_id)
);

CREATE INDEX ix_doc_perm_principal ON document_permissions (principal_type, principal_id);

-- ---------------------------------------------------------------------
-- 4. Log callback: audit + chống xử lý trùng (ONLYOFFICE có thể retry)
-- ---------------------------------------------------------------------
CREATE TABLE office_callback_log
(
    id             BIGSERIAL PRIMARY KEY,
    document_id    UUID         NOT NULL REFERENCES documents (id) ON DELETE CASCADE,
    editor_key     VARCHAR(128) NOT NULL,
    status         SMALLINT     NOT NULL, -- 1,2,3,4,6,7
    file_url       TEXT,                  -- url file đã sửa (status 2/6)
    payload        JSONB        NOT NULL,
    result_version INT,                   -- version được tạo ra (nếu có)
    error          TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX ix_callback_doc ON office_callback_log (document_id, created_at DESC);
-- Status 2 chỉ xử lý 1 lần cho mỗi phiên
CREATE UNIQUE INDEX ux_callback_close_once ON office_callback_log (editor_key) WHERE status = 2;


-- -- =====================================================================
-- -- QUERY MẪU
-- -- =====================================================================
--
-- -- [Q1] GET /api/office/{id}/config
-- --      Lấy metadata + version + quyền cao nhất của user (theo userId hoặc role)
-- SELECT d.id,
--        d.name,
--        d.file_ext,
--        d.bucket,
--        d.object_key,
--        d.current_version,
--        d.editor_key,
--        d.status,
--        CASE
--            WHEN d.owner_id = :userId THEN 'OWNER'::doc_permission
--            ELSE MAX(p.permission) END AS effective_permission
-- FROM documents d
--          LEFT JOIN document_permissions p
--                    ON p.document_id = d.id
--                        AND (p.expires_at IS NULL OR p.expires_at > now())
--                        AND ((p.principal_type = 'USER' AND p.principal_id = :userId)
--                            OR (p.principal_type = 'ROLE' AND p.principal_id = ANY (:roles)))
-- WHERE d.id = :docId
--   AND d.status <> 'DELETED'
-- GROUP BY d.id;
-- -- effective_permission NULL  -> 403
-- -- EDIT / OWNER               -> permissions.edit = true
-- -- status = 'LOCKED'          -> ép edit = false
--
--
-- -- [Q2] Callback status 2 (đóng phiên): tạo version mới + XOAY editor_key
-- --      Chạy trong 1 transaction, sau khi đã putObject lên MinIO thành công
-- BEGIN;
--
-- INSERT INTO office_callback_log (document_id, editor_key, status, file_url, payload)
-- VALUES (:docId, :editorKey, 2, :fileUrl, :payload::jsonb);
-- -- Vi phạm ux_callback_close_once => đã xử lý rồi => ROLLBACK, trả {"error":0}
--
-- UPDATE documents
-- SET current_version = current_version + 1,
--     object_key      = :newObjectKey,
--     size_bytes      = :size,
--     editor_key      = replace(gen_random_uuid()::text, '-', ''),
--     updated_at      = now(),
--     updated_by      = :lastUser
-- WHERE id = :docId
--   AND editor_key = :editorKey -- chặn callback của phiên cũ
--     RETURNING current_version;
--
-- INSERT INTO document_versions (document_id, version, object_key, size_bytes, checksum, source, editor_key, changed_by)
-- VALUES (:docId, :newVersion, :newObjectKey, :size, :sha256, 'CLOSE_SAVE', :editorKey, :users);
--
-- COMMIT;
--
--
-- -- [Q3] Callback status 6 (force save): tạo version mới, GIỮ NGUYÊN editor_key
-- UPDATE documents
-- SET current_version = current_version + 1,
--     object_key      = :newObjectKey,
--     size_bytes      = :size,
--     updated_at      = now(),
--     updated_by      = :user
-- WHERE id = :docId RETURNING current_version;
-- -- rồi INSERT document_versions với source = 'FORCE_SAVE'
--
--
-- -- [Q4] Lịch sử version
-- SELECT version, source, changed_by, size_bytes, created_at
-- FROM document_versions
-- WHERE document_id = :docId
-- ORDER BY version DESC;
--
--
-- -- [Q5] Danh sách tài liệu user được truy cập
-- SELECT d.id, d.name, d.current_version, d.updated_at
-- FROM documents d
-- WHERE d.status <> 'DELETED'
--   AND (d.owner_id = :userId
--     OR EXISTS (SELECT 1
--                FROM document_permissions p
--                WHERE p.document_id = d.id
--                  AND (p.expires_at IS NULL OR p.expires_at > now())
--                  AND ((p.principal_type = 'USER' AND p.principal_id = :userId)
--                    OR (p.principal_type = 'ROLE' AND p.principal_id = ANY (:roles)))))
-- ORDER BY d.updated_at DESC LIMIT 50;
