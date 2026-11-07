# WebSocket Feature – Angular 22 × Spring Boot 4.1.2 (STOMP)

Tính năng nhắn tin realtime hai chiều giữa Angular và Spring Boot, dùng giao thức **STOMP over WebSocket**:

- **Chat broadcast**: một người gửi, tất cả client đang mở trang đều nhận.
- **Thông báo riêng**: server đẩy tin cho đúng một user (ví dụ: hồ sơ giải ngân chờ duyệt).
- **Echo / lỗi riêng**: phản hồi chỉ gửi về cho người vừa gửi.
- **Tự reconnect**: rớt mạng thì tự kết nối lại, tự subscribe lại và lấy token mới.

---

## 1. Tech stack

| Tầng | Công nghệ |
|---|---|
| Frontend | Angular 22 (standalone, signals, OnPush), `@stomp/rx-stomp` |
| Backend | Spring Boot 4.1.2, Spring Framework 7, `spring-boot-starter-websocket`, Jackson 3 |
| Server | Tomcat 11 (embedded) |
| Broker | Spring Simple Broker (in-memory); production thì dùng RabbitMQ STOMP relay |
| Giao thức | WebSocket (RFC 6455) + STOMP 1.2 |

---

## 2. Kiến trúc tổng quan

```mermaid
flowchart LR
    subgraph Browser["🌐 Browser – Angular 22"]
        direction TB
        C["WebsocketComponent<br/>(signals)"]
        S["StompService<br/>@Injectable root"]
        R["RxStomp<br/>@stomp/rx-stomp"]
        C -- "connect / publish / watch" --> S
        S --> R
    end

    subgraph Server["☕ Spring Boot 4.1.2"]
        direction TB
        EP["STOMP Endpoint<br/>/ws"]
        IN["clientInboundChannel"]
        INT["TestAuthInterceptor<br/>(CONNECT → Principal)"]
        CTRL["ChatWsController<br/>@MessageMapping"]
        BRK["Simple Broker<br/>/topic · /queue"]
        UDR["UserDestinationResolver<br/>/user/** → session"]
        OUT["clientOutboundChannel"]
        REST["WsTestController<br/>REST /api/ws-test"]
        TPL["SimpMessagingTemplate"]
        EVT["WsEventListener<br/>Connected / Disconnect"]

        EP --> IN --> INT
        INT -- "/app/**" --> CTRL
        INT -- "/topic/** · /queue/**" --> BRK
        CTRL -- "@SendTo / @SendToUser" --> BRK
        REST --> TPL --> BRK
        EVT --> TPL
        BRK --> UDR --> OUT
        BRK --> OUT
        OUT --> EP
    end

    CURL["🧪 curl / Postman"] -- "HTTP POST" --> REST
    R <== "ws://localhost:8080/ws<br/>STOMP frames" ==> EP
```

### Quy ước destination

| Hướng | Destination | Xử lý bởi | Payload |
|---|---|---|---|
| Client → Server | `/app/chat.send` | `ChatWsController#send` | `{ "content": "hello" }` |
| Client → Server | `/app/chat.echo` | `ChatWsController#echo` | `{ "content": "abc" }` |
| Server → Tất cả | `/topic/chat` | Simple Broker | `ChatMessage` |
| Server → 1 user | `/user/queue/notifications` | UserDestinationResolver | `NotificationMessage` |
| Server → 1 user | `/user/queue/errors` | `@MessageExceptionHandler` | `ErrorMessage` |

> Prefix `/app` dành cho message đi vào `@MessageMapping`. Prefix `/topic` và `/queue` đi thẳng vào broker. Prefix `/user` được Spring đổi thành queue riêng theo session, ví dụ `/queue/notifications-user{sessionId}`.

---

## 3. Cấu trúc thư mục

### Frontend

```
src/
├── environments/environment.ts          # wsUrl: 'ws://localhost:8080/ws'
└── app/
    ├── core/
    │   ├── models/ws-message.ts         # ChatMessage, NotificationMessage, WsError, WsStatus
    │   └── services/stomp.service.ts    # Bọc RxStomp: connect/disconnect/watch/publish
    └── features/
        └── websocket/
            ├── websocket.component.ts   # State bằng signal, subscribe 3 kênh
            ├── websocket.component.html # Chat + Thông báo + Kết nối
            └── websocket.component.scss
```

### Backend

```
com.example.websocket/
├── config/
│   ├── WebSocketConfig.java       # Endpoint /ws, broker, heartbeat, interceptor
│   ├── TestAuthInterceptor.java   # CONNECT: header username → Principal
│   └── WsEventListener.java       # Log + broadcast vào/rời phòng
├── controller/
│   ├── ChatWsController.java      # @MessageMapping chat.send / chat.echo
│   └── WsTestController.java      # REST: online, notify, broadcast
└── dto/WsDtos.java                # Record: request/response/principal
```

---

## 4. Sequence flows

### 4.1. Kết nối (Handshake + STOMP CONNECT)

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as WebsocketComponent
    participant S as StompService
    participant R as RxStomp
    participant T as Tomcat /ws
    participant I as TestAuthInterceptor
    participant E as WsEventListener
    participant B as Simple Broker

    U->>C: Nhập "duy" → bấm Kết nối
    C->>S: connect("duy", getToken)
    S->>R: configure({ brokerURL, heartbeat, beforeConnect })
    S->>R: activate()
    R-->>S: connectionState$ = CONNECTING
    S-->>C: status() = CONNECTING (badge vàng)

    R->>R: beforeConnect() → connectHeaders { username, Authorization }
    R->>T: HTTP GET /ws<br/>Upgrade: websocket
    T-->>R: 101 Switching Protocols

    R->>T: STOMP CONNECT<br/>username:duy<br/>heart-beat:10000,10000
    T->>I: preSend(CONNECT)
    I->>I: accessor.setUser(StompPrincipal("duy"))
    I-->>T: message (đã gắn Principal)
    T-->>R: STOMP CONNECTED<br/>heart-beat:10000,10000
    R-->>S: connectionState$ = OPEN
    S-->>C: status() = OPEN (badge xanh)

    T->>E: SessionConnectedEvent(user=duy)
    E->>B: convertAndSend(/topic/chat, "duy đã vào phòng")

    Note over R,T: RxStomp gửi SUBSCRIBE cho các watch() đã đăng ký từ trước
    R->>T: SUBSCRIBE /topic/chat
    R->>T: SUBSCRIBE /user/queue/notifications
    R->>T: SUBSCRIBE /user/queue/errors
```

### 4.2. Chat broadcast (`/app/chat.send` → `/topic/chat`)

```mermaid
sequenceDiagram
    autonumber
    actor A as duy (Tab 1)
    participant CA as Component Tab 1
    participant SV as Spring /ws
    participant CT as ChatWsController
    participant BR as Simple Broker
    participant CB as Component Tab 2
    actor L as lan (Tab 2)

    A->>CA: Gõ "hello" → Gửi
    CA->>SV: SEND /app/chat.send<br/>{"content":"hello"}
    SV->>CT: send(@Valid req, Principal=duy)
    CT->>CT: new ChatMessage("duy","hello",Instant.now())
    CT->>BR: @SendTo("/topic/chat")

    par Gửi tới mọi subscriber
        BR-->>CA: MESSAGE /topic/chat<br/>{"sender":"duy",...}
        CA->>CA: messages.update() → bubble phải (xanh)
    and
        BR-->>CB: MESSAGE /topic/chat<br/>{"sender":"duy",...}
        CB->>CB: messages.update() → bubble trái
        CB-->>L: Hiển thị tin mới
    end
```

### 4.3. Thông báo riêng từ server (REST → `/user/queue/notifications`)

Đây là luồng dùng cho nghiệp vụ, ví dụ khi duyệt xong hồ sơ thì báo cho người tạo.

```mermaid
sequenceDiagram
    autonumber
    actor Ops as Tester / Service nghiệp vụ
    participant REST as WsTestController
    participant REG as SimpUserRegistry
    participant TPL as SimpMessagingTemplate
    participant UDR as UserDestinationResolver
    participant BR as Simple Broker
    participant L as Tab "lan"
    participant D as Tab "duy"

    Ops->>REST: POST /api/ws-test/notify/lan<br/>{"type":"WARNING","title":"Giải ngân",...}
    REST->>REG: getUser("lan")
    alt lan không online
        REG-->>REST: null
        REST-->>Ops: 404 Not Found
    else lan đang online
        REG-->>REST: SimpUser(lan)
        REST->>TPL: convertAndSendToUser("lan","/queue/notifications",msg)
        TPL->>UDR: /user/lan/queue/notifications
        UDR->>UDR: Tìm session của lan<br/>→ /queue/notifications-user{sessionId}
        UDR->>BR: forward
        BR-->>L: MESSAGE /user/queue/notifications
        L->>L: notifications.update() → thẻ vàng
        Note over D: Tab "duy" KHÔNG nhận
        REST-->>Ops: 200 OK + NotificationMessage
    end
```

### 4.4. Echo và lỗi validation (`@SendToUser`)

```mermaid
sequenceDiagram
    autonumber
    participant C as Component (duy)
    participant SV as Spring /ws
    participant CT as ChatWsController
    participant BR as Broker

    rect rgb(235, 245, 255)
    Note over C,BR: Echo – chỉ người gửi nhận
    C->>SV: SEND /app/chat.echo {"content":"xin chào"}
    SV->>CT: echo(req)
    CT->>BR: @SendToUser("/queue/notifications")
    BR-->>C: MESSAGE /user/queue/notifications
    end

    rect rgb(255, 240, 240)
    Note over C,BR: Payload sai – content rỗng hoặc > 500 ký tự
    C->>SV: SEND /app/chat.send {"content":""}
    SV->>CT: send(@Valid req)
    CT--xCT: MethodArgumentNotValidException
    CT->>CT: @MessageExceptionHandler onInvalid()
    CT->>BR: @SendToUser("/queue/errors")
    BR-->>C: MESSAGE /user/queue/errors<br/>{"code":"VALIDATION_ERROR",...}
    C->>C: lastError.set() → banner đỏ
    end
```

### 4.5. Mất kết nối và tự reconnect

```mermaid
sequenceDiagram
    autonumber
    participant C as Component
    participant R as RxStomp
    participant SV as Spring /ws
    participant E as WsEventListener

    Note over R,SV: Đang OPEN, heartbeat 10s mỗi chiều
    SV--xR: Server restart / rớt mạng
    R-->>C: connectionState$ = CLOSED (badge xám)
    SV->>E: SessionDisconnectEvent(duy)
    E->>E: broadcast "duy đã rời phòng"

    loop Mỗi 3s (reconnectDelay)
        R-->>C: CONNECTING
        R->>R: beforeConnect() → lấy token MỚI NHẤT
        R->>SV: GET /ws (Upgrade)
        SV--xR: Connection refused
        R-->>C: CLOSED
    end

    SV->>SV: Server up lại
    R->>SV: GET /ws → 101
    R->>SV: CONNECT (username, token mới)
    SV-->>R: CONNECTED
    R-->>C: OPEN (badge xanh)
    Note over R,SV: _connectedPre$ emit → tự SUBSCRIBE lại mọi watch()
    R->>SV: SUBSCRIBE /topic/chat
    R->>SV: SUBSCRIBE /user/queue/notifications
    R->>SV: SUBSCRIBE /user/queue/errors
```

### 4.6. Ngắt kết nối chủ động

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as Component
    participant S as StompService
    participant R as RxStomp
    participant SV as Spring /ws

    U->>C: Bấm "Ngắt kết nối"
    C->>S: disconnect()
    S->>R: deactivate()
    R-->>C: CLOSING
    R->>SV: STOMP DISCONNECT
    R->>SV: WebSocket close frame
    SV->>SV: SessionDisconnectEvent → broadcast "rời phòng"
    R-->>C: CLOSED
    S->>S: username.set(null)
    Note over R: Tắt auto-reconnect cho tới khi connect() lại
```

### 4.7. Vòng đời trạng thái kết nối

```mermaid
stateDiagram-v2
    [*] --> CLOSED
    CLOSED --> CONNECTING: connect() / reconnectDelay hết
    CONNECTING --> OPEN: nhận CONNECTED
    CONNECTING --> CLOSED: handshake lỗi / STOMP ERROR
    OPEN --> CLOSED: rớt mạng / server down
    OPEN --> CLOSING: disconnect()
    CLOSING --> CLOSED: socket đóng xong
    CLOSED --> [*]: deactivate (không reconnect)
```

---

## 5. Cài đặt và chạy

### Backend

```groovy
// build.gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-websocket'
    implementation 'org.springframework.boot:spring-boot-starter-validation'
    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'
}
```

```bash
./gradlew clean bootRun        # http://localhost:8080
```

### Frontend

```bash
npm i @stomp/rx-stomp
ng serve                       # http://localhost:4200/websocket
```

---

## 6. Kịch bản test

| # | Thao tác | Kết quả mong đợi |
|---|---|---|
| 1 | Tab 1 kết nối với tên `duy` | Badge **OPEN**, hiện "duy đã vào phòng" |
| 2 | Tab 2 kết nối với tên `lan` | Cả 2 tab thấy "lan đã vào phòng" |
| 3 | Tab 1 gõ `hello` | Tab 1 thấy bubble phải, tab 2 thấy bubble trái |
| 4 | Tab 1 gõ `/echo xin chào` | Chỉ tab 1 nhận trong khung Thông báo |
| 5 | Gửi tin rỗng qua devtools | Banner đỏ `VALIDATION_ERROR` |
| 6 | `curl` notify `lan` | Chỉ tab 2 nhận thẻ vàng |
| 7 | Tắt BE rồi bật lại | Badge CLOSED → CONNECTING → OPEN, tự nhận tin lại |
| 8 | Tab 2 bấm Ngắt kết nối | Tab 1 thấy "lan đã rời phòng" |

```bash
# User đang online
curl http://localhost:8080/api/ws-test/online
# ["duy","lan"]

# Thông báo riêng
curl -X POST http://localhost:8080/api/ws-test/notify/lan \
  -H 'Content-Type: application/json' \
  -d '{"type":"WARNING","title":"Giải ngân","body":"Hồ sơ #FX-1023 chờ duyệt"}'

# Broadcast từ server
curl -X POST "http://localhost:8080/api/ws-test/broadcast?content=B%E1%BA%A3o%20tr%C3%AC%2023h"
```

---

## 7. Troubleshooting

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `Invalid character found in method name [0x160x030x01...]` | Client gửi TLS (`wss://`, `https://`) vào port HTTP | Đổi thành `ws://localhost:8080/ws` và `http://` |
| `variable xxx not initialized in the default constructor` | Lombok không chạy | Thêm `annotationProcessor`, nâng Lombok, bật annotation processing trong IDE |
| Badge kẹt ở CONNECTING, console báo 403 | CORS origin không khớp | `setAllowedOriginPatterns("http://localhost:4200")` |
| Badge kẹt ở CONNECTING, console báo 401/403 (có Security) | `/ws/**` bị Spring Security chặn | `requestMatchers("/ws/**").permitAll()` |
| Gửi chat thì BE báo NPE ở `principal.getName()` | Interceptor chưa gắn Principal | Kiểm tra đã đăng ký `configureClientInboundChannel` |
| Không nhận được `/user/queue/...` | Không có Principal, hoặc gửi sai username | `GET /api/ws-test/online` để xem đúng tên |
| Trang `https://` không kết nối được `ws://` | Trình duyệt chặn mixed content | Dùng proxy Angular (`"ws": true`) hoặc bật SSL cho BE |

---

## 8. Hướng lên production

```mermaid
flowchart LR
    B1["Browser"] -- "wss://" --> LB["Nginx / LB<br/>Upgrade + sticky"]
    B2["Browser"] -- "wss://" --> LB
    LB --> A1["Spring Boot #1"]
    LB --> A2["Spring Boot #2"]
    A1 <-- "STOMP relay :61613" --> MQ[("RabbitMQ<br/>rabbitmq_stomp")]
    A2 <-- "STOMP relay :61613" --> MQ
    KC["Keycloak"] -. "JWKS" .-> A1
    KC -. "JWKS" .-> A2
```

| Hạng mục | Dev (hiện tại) | Production |
|---|---|---|
| Xác thực | `TestAuthInterceptor` (header `username`) | `JwtChannelInterceptor` dùng `JwtDecoder` (Keycloak), lấy `preferred_username` |
| Broker | `enableSimpleBroker` (in-memory) | `enableStompBrokerRelay` → RabbitMQ, để các instance nhìn thấy message của nhau |
| Transport | `ws://` | `wss://`, kết thúc TLS ở Nginx |
| Nginx | — | `proxy_set_header Upgrade $http_upgrade; Connection "upgrade"; proxy_read_timeout 60s` |
| Token hết hạn | Token cố định | `beforeConnect` refresh token trước mỗi lần reconnect |
| Gửi khi offline | `retryIfDisconnected: false` | Giữ `false` cho lệnh nghiệp vụ; với lệnh quan trọng thì dùng `receipt` + `asyncReceipt()` |
| Endpoint test | `/api/ws-test/**` | Xóa, hoặc giới hạn bằng `@Profile("dev")` |
