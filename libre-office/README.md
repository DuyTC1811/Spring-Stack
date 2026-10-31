# Tích hợp ONLYOFFICE Docs vào Angular + Spring Boot

Tài liệu mô tả kiến trúc nhúng trình soạn thảo văn bản (docx/xlsx/pptx) vào ứng dụng Angular 22, sử dụng **ONLYOFFICE Docs Community Edition** (tự host, AGPL-3.0), backend **Spring Boot**, lưu trữ file trên **MinIO**, metadata trên **Oracle**.

---

## 1. Tổng quan kiến trúc

```mermaid
flowchart LR
    subgraph Client
        FE["Angular 22<br/>@onlyoffice/document-editor-angular"]
    end

    subgraph Internal["Mạng nội bộ / DC"]
        OO["ONLYOFFICE Docs<br/>(Document Server)"]
        BE["Spring Boot<br/>Office API"]
        MINIO[("MinIO<br/>bucket: docs")]
        DB[("Oracle<br/>document metadata")]
    end

    FE -- "(1) GET /api/office/{id}/config" --> BE
    FE -- "(A) load api.js + WebSocket" --> OO
    OO -- "(2) GET document.url (presigned)" --> MINIO
    OO -- "(3) POST callbackUrl" --> BE
    BE -- "(4) GET file đã sửa" --> OO
    BE -- "(5) putObject" --> MINIO
    BE -- "metadata / version" --> DB
```

**Nguyên tắc:** ONLYOFFICE **không lưu trữ file**. Nó chỉ là bộ soạn thảo:
- **Lấy file** từ `document.url` (presigned URL của MinIO).
- **Trả file** sau khi sửa bằng cách gọi `callbackUrl` trên Spring Boot.

Browser **nói chuyện trực tiếp** với ONLYOFFICE để soạn thảo (WebSocket). Còn các bước tải/lưu file là **server-to-server** giữa ONLYOFFICE và backend, browser không tham gia.

---

## 2. Thành phần

| Thành phần | Công nghệ | Trách nhiệm |
|---|---|---|
| **Frontend** | Angular 22, `@onlyoffice/document-editor-angular` | Lấy config từ backend, render editor, xử lý event (`onDocumentReady`, lỗi load) |
| **Office API** | Spring Boot | Cấp config editor (phân quyền, `document.key`, presigned URL); nhận callback, lưu file mới, tăng version |
| **ONLYOFFICE Docs** | Docker `onlyoffice/documentserver` | Render và soạn thảo tài liệu, đồng bộ cộng tác realtime, convert định dạng, gọi callback khi lưu |
| **MinIO** | Object storage | Lưu file gốc và các version |
| **Oracle** | RDBMS | Metadata: tên file, owner, version hiện tại, lịch sử chỉnh sửa |

---

## 3. API backend

| Method | Endpoint | Gọi bởi | Mô tả |
|---|---|---|---|
| `GET` | `/api/office/{id}/config` | Angular (có xác thực người dùng) | Trả config editor |
| `POST` | `/office/callback/{id}` | ONLYOFFICE | Nhận trạng thái; status `2`/`6` → tải file mới, lưu MinIO, tăng version; luôn trả `{"error":0}` |

### Ví dụ config trả về FE

```json
{
  "documentType": "word",
  "document": {
    "fileType": "docx",
    "key": "abc-123_5",
    "title": "phieu-giai-ngan.docx",
    "url": "https://minio.internal/docs/abc-123.docx?X-Amz-Signature=...",
    "permissions": { "edit": true, "download": true }
  },
  "editorConfig": {
    "callbackUrl": "http://office-api.internal:8080/office/callback/abc-123",
    "lang": "vi",
    "user": { "id": "u001", "name": "Nguyễn Văn A" },
    "customization": { "forcesave": true }
  }
}
```

> **`document.key`** = `{fileId}_{version}`. Bắt buộc **đổi key sau mỗi lần lưu**, nếu không ONLYOFFICE dùng bản cache cũ. Ký tự hợp lệ: `0-9 a-z A-Z . = _ -`, tối đa 128 ký tự.

### Bảng status callback

| Status | Ý nghĩa | Backend xử lý |
|---|---|---|
| `1` | Đang được chỉnh sửa | Bỏ qua |
| `2` | Tất cả người dùng đã đóng, có thay đổi | **Tải `url`, lưu, tăng version** |
| `3` | Lỗi khi lưu | Log, cảnh báo |
| `4` | Đóng, không có thay đổi | Bỏ qua |
| `6` | Force save (người dùng bấm Save) | **Tải `url`, lưu, tăng version** |
| `7` | Lỗi force save | Log, cảnh báo |

---

## 4. Sequence diagram

### 4.1 Mở tài liệu

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng
    participant FE as Angular
    participant BE as Spring Boot
    participant DB as Oracle
    participant M as MinIO
    participant OO as ONLYOFFICE

    U->>FE: Mở tài liệu (fileId)
    FE->>BE: GET /api/office/{id}/config
    BE->>DB: Lấy metadata, version, kiểm tra quyền
    DB-->>BE: name, ext, version, canWrite
    BE->>M: Tạo presigned GET URL (TTL 2h)
    M-->>BE: presignedUrl
    BE-->>FE: config (key = id_version, url, callbackUrl, user)
    FE->>OO: Tải api.js, khởi tạo DocEditor(config)
    OO->>M: GET presignedUrl
    M-->>OO: file docx
    OO->>OO: Convert sang định dạng nội bộ, cache theo key
    OO-->>FE: Render editor (WebSocket)
    OO->>BE: POST callback (status=1, users=[u001])
    BE-->>OO: {"error":0}
    FE-->>U: Hiển thị tài liệu
```

### 4.2 Chỉnh sửa và lưu khi đóng (status 2)

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng
    participant FE as Angular
    participant OO as ONLYOFFICE
    participant BE as Spring Boot
    participant M as MinIO
    participant DB as Oracle

    U->>FE: Gõ / sửa nội dung
    FE->>OO: Gửi thay đổi qua WebSocket
    OO->>OO: Lưu thay đổi tạm (autosave nội bộ)
    U->>FE: Đóng tab / rời trang
    FE-xOO: Ngắt kết nối
    Note over OO: Chờ ~10s sau khi người cuối cùng rời đi
    OO->>OO: Build file docx mới
    OO->>BE: POST /office/callback/{id} (status=2, url)
    BE->>OO: GET url (file đã sửa)
    OO-->>BE: file docx
    BE->>M: putObject (ghi version mới)
    BE->>DB: version = version + 1, lưu lịch sử
    BE-->>OO: {"error":0}
    Note over OO: Xóa cache của key cũ
```

### 4.3 Force save (người dùng bấm Save, status 6)

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng
    participant FE as Angular
    participant OO as ONLYOFFICE
    participant BE as Spring Boot
    participant M as MinIO
    participant DB as Oracle

    U->>FE: Bấm Save (Ctrl+S)
    FE->>OO: Yêu cầu force save
    OO->>BE: POST /office/callback/{id} (status=6, url)
    BE->>OO: GET url
    OO-->>BE: file docx
    BE->>M: putObject
    BE->>DB: version = version + 1
    BE-->>OO: {"error":0}
    OO-->>FE: Lưu thành công
    Note over U,OO: Người dùng vẫn tiếp tục sửa trong cùng phiên
```

### 4.4 Nhiều người cùng chỉnh sửa

```mermaid
sequenceDiagram
    autonumber
    actor A as User A
    actor B as User B
    participant OO as ONLYOFFICE
    participant BE as Spring Boot

    A->>OO: Mở tài liệu (key = abc-123_5)
    OO->>BE: callback status=1 users=[A]
    B->>OO: Mở cùng tài liệu (cùng key)
    OO->>BE: callback status=1 users=[A,B]
    A->>OO: Sửa đoạn 1
    OO-->>B: Đồng bộ thay đổi realtime
    B->>OO: Sửa đoạn 2
    OO-->>A: Đồng bộ thay đổi realtime
    A->>OO: Đóng
    OO->>BE: callback status=1 users=[B]
    B->>OO: Đóng
    OO->>BE: callback status=2 url=... (một file đã gộp)
    BE-->>OO: {"error":0}
```

> Các user cùng sửa **phải nhận cùng `document.key`**, ONLYOFFICE dựa vào key để gộp vào một phiên chung.

---

## 5. Triển khai

### Docker Compose (ONLYOFFICE)

```yaml
services:
  onlyoffice:
    image: onlyoffice/documentserver:8.3   # pin version, không dùng latest ở production
    ports: ["8081:80"]
    environment:
      - JWT_ENABLED=false                  # xem mục 6
      - ALLOW_PRIVATE_IP_ADDRESS=true      # cho phép gọi MinIO/backend ở IP nội bộ
    volumes:
      - oo_data:/var/www/onlyoffice/Data
      - oo_lib:/var/lib/onlyoffice
      - oo_db:/var/lib/postgresql
      - ./fonts:/usr/share/fonts/truetype/custom
volumes: { oo_data: {}, oo_lib: {}, oo_db: {} }
```

Sau khi thêm font tiếng Việt:

```bash
docker exec onlyoffice /usr/bin/documentserver-generate-allfonts.sh
curl http://localhost:8081/healthcheck   # trả về true
```

### Yêu cầu kết nối mạng

| Từ | Đến | Mục đích |
|---|---|---|
| Browser | ONLYOFFICE `:8081` | Tải `api.js`, WebSocket soạn thảo |
| Browser | Spring Boot | Lấy config |
| ONLYOFFICE | MinIO | Tải file gốc (presigned URL) |
| ONLYOFFICE | Spring Boot | Gọi callback |
| Spring Boot | ONLYOFFICE | Tải file đã sửa (`url` trong callback) |

> `callbackUrl` và `document.url` phải là địa chỉ **container ONLYOFFICE truy cập được**. Không dùng `localhost`.

---

## 6. Bảo mật

### Chế độ hiện tại: tắt JWT (`JWT_ENABLED=false`), chỉ dùng cho dev/POC

Các biện pháp bù đắp bắt buộc:

1. **Giới hạn IP:** chỉ IP/subnet của ONLYOFFICE được gọi `/office/callback/**`.
2. **Chống SSRF:** trong callback, chỉ tải file khi `url` có host đúng là ONLYOFFICE.
3. **Presigned URL ngắn hạn:** `document.url` hết hạn sau 2h, không public bucket.
4. **Không expose cổng ONLYOFFICE ra Internet:** chỉ đi qua reverse proxy nội bộ (TLS, mở WebSocket).

### Khuyến nghị UAT/Production: bật JWT

- `JWT_ENABLED=true`, `JWT_SECRET` ≥ 32 ký tự, dùng chung giữa ONLYOFFICE và backend.
- Backend ký toàn bộ config (HS256), gắn vào trường `token`.
- Backend verify `token` trong body callback, chỉ tin dữ liệu trong claims đã ký.
- Thư viện: tái sử dụng **Nimbus JOSE + JWT** (có sẵn nếu dùng Spring Security OAuth2), hoặc `jjwt`.

---

## 7. Giới hạn và lưu ý

- **Community Edition giới hạn 20 kết nối đồng thời.** Người dùng thứ 21 chỉ được mở ở chế độ xem. Cần theo dõi số người dùng trước khi mở rộng phạm vi.
- **License AGPL-3.0:** dùng nguyên bản thì không phát sinh nghĩa vụ. Nếu sửa source ONLYOFFICE thì phải cung cấp source đã sửa cho người dùng. Ứng dụng Angular/Spring Boot gọi qua API không bị ảnh hưởng.
- **Lưu khi đóng có độ trễ khoảng 10 giây** sau khi người cuối cùng rời đi. Muốn lưu ngay thì dùng force save (`customization.forcesave: true`).
- **Idempotency:** callback có thể bị gửi lại. Backend nên kiểm tra `key`/version để tránh tăng version hai lần.

### Lỗi thường gặp

| Lỗi | Nguyên nhân | Cách xử lý |
|---|---|---|
| *Download failed* | ONLYOFFICE không gọi được `document.url` | Kiểm tra mạng, `ALLOW_PRIVATE_IP_ADDRESS`, presigned URL hết hạn |
| *Document security token is not correctly formed* | JWT đang bật ở server nhưng config không có `token` | Tắt JWT hoặc ký config |
| Mở ra bản cũ | `document.key` không đổi sau khi lưu | Key gắn với version |
| Không lưu được | Callback không trả `{"error":0}` hoặc không gọi được callback | Kiểm tra log ONLYOFFICE, firewall |