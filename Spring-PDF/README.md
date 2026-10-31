# Spring-PDF

Demo các thao tác xử lý PDF trên Spring Boot 4 / Java 25, dùng hai thư viện:

| Thư viện | Phiên bản | Dùng cho |
|---|---|---|
| **OpenPDF** (`com.github.librepdf:openpdf`) | 3.0.0 | Sinh PDF đơn giản theo mô hình `Document` / `Paragraph` (`/demo/invoice`, `/demo/pdf`) |
| **Apache PDFBox** (`org.apache.pdfbox:pdfbox`) | 3.0.8 | Vẽ PDF cấp thấp, trích text, tách/gộp, form, render ảnh, in, ký số |

Ngoài phần PDF, project còn có một cơ chế **Strategy Executor** tự đăng ký bean theo kiểu generic (`POST /demo/{type}`).

> **Trạng thái:** project đang dang dở. Phần lớn method trong `PDFServiceImpl` đang bị comment, và
> `IPDFService` mới khai báo `createPDF()` / `createImagePDF()`. Xem mục [Trạng thái hiện tại](#trạng-thái-hiện-tại)
> trước khi build.

---

## 1. Kiến trúc tổng quan

```mermaid
flowchart LR
    Client([HTTP Client])

    subgraph Web["Web layer"]
        DC[DemoController<br/>/demo/**]
    end

    subgraph Service["Service layer"]
        IPS[[IPDFService]]
        PSI[PDFServiceImpl]
        SE[StrategyExecutor&lt;T,R&gt;]
    end

    subgraph Strategies["Strategy beans"]
        NS[NotifyStrategy<br/>type = EMAIL]
        DS[DemoStrategy<br/>type = demo]
    end

    subgraph Infra["Bootstrap"]
        REG[StrategyExecutorRegistrar<br/>BeanDefinitionRegistryPostProcessor]
    end

    subgraph Libs["Thư viện PDF"]
        OP[(OpenPDF)]
        PB[(PDFBox)]
        FONT[/Font TTF tiếng Việt/]
    end

    Client -->|REST / multipart| DC
    DC --> IPS
    IPS -. implements .- PSI
    PSI --> OP
    PSI --> PB
    PSI --> FONT
    DC -->|"/demo/{type}"| SE
    SE --> NS
    SE --> DS
    REG -. đăng ký bean lúc khởi động .-> SE
```

### Cấu trúc package

```
org.example.springpdf
├── SpringPdfApplication.java          # main
├── StrategyExecutorAutoConfig.java    # (đã comment) cấu hình cũ, thay bằng AutoConfiguration
├── controller/
│   └── DemoController.java            # toàn bộ endpoint /demo/**
├── service/
│   ├── IPDFService.java               # interface nghiệp vụ PDF
│   ├── PDFServiceImpl.java            # cài đặt bằng OpenPDF + PDFBox
│   ├── Strategy.java                  # Strategy<T, R> { type(); execute(T) }
│   └── StrategyExecutor.java          # map type -> Strategy, dispatch theo type
├── handler/
│   ├── NotifyStrategy.java            # Strategy<NotifyRequest, NotifyResult>
│   └── DemoStrategy.java              # Strategy<Void, Void>
├── model/
│   ├── NotifyRequest.java
│   └── NotifyResult.java
└── registrar/
    └── StrategyExecutorRegistrar.java # tự sinh bean StrategyExecutor theo cặp generic

resources/META-INF/spring/
└── org.springframework.boot.autoconfigure.AutoConfiguration.imports  # đăng ký Registrar
```

### Nguyên tắc thiết kế

- **Controller mỏng:** chỉ đọc `MultipartFile` → `byte[]`, gọi service, rồi bọc kết quả bằng helper
  `file(body, filename, mediaType)` (đặt `Content-Type` + `Content-Disposition: attachment` với tên file UTF-8).
- **Service thuần `byte[]`:** mọi method nhận/trả `byte[]`, không phụ thuộc Servlet API → dễ unit test,
  dễ tái sử dụng (queue, batch...).
- **Xử lý in-memory:** PDF được load bằng `Loader.loadPDF(byte[])` và ghi ra `ByteArrayOutputStream`
  (helper `save(doc)`). Kết quả nhiều file (split, render all) được đóng gói ZIP (helper `zip(...)`).
  Ngoại lệ: `/demo/invoice` stream thẳng vào `HttpServletResponse`, `preflight` cần file tạm.
- **Tọa độ:** PDF dùng gốc **dưới-trái**; các API nhận vùng/vị trí từ UI (`/text/area`, `/sign`) dùng gốc
  **trên-trái**, đơn vị point (1pt = 1/72 inch).
- **Font tiếng Việt:** font chuẩn của PDF (Helvetica...) không có dấu tiếng Việt, nên phải nhúng font TTF
  (`loadFont(doc, subset)`). `subset=true` cho tài liệu thường (file nhỏ), `subset=false` cho AcroForm
  (người dùng gõ ký tự bất kỳ).

---

## 2. Danh sách API

Base path: `/demo`

| # | Method | Path | Input | Output | Thư viện |
|---|---|---|---|---|---|
| 0 | GET | `/invoice` | – | `invoice.pdf` (stream) | OpenPDF |
| 0 | GET | `/pdf` | – | `demo.pdf` | OpenPDF |
| 1 | POST | `/create` | `customer`, part `logo` (tùy chọn) | `hoa-don.pdf` | PDFBox |
| 2 | POST | `/text` | part `file`, `startPage`, `endPage`, `sortByPosition`, `password` | JSON `TextResult` | PDFBox |
| 2 | POST | `/text/area` | part `file`, `page`, `x`, `y`, `w`, `h` | JSON `{ "text": ... }` | PDFBox |
| 3 | POST | `/split` | part `file`, `pagesPerFile` hoặc `ranges="1-2,3"` | `split.zip` | PDFBox |
| 3 | POST | `/merge` | part `files` (nhiều file, đúng thứ tự) | `merged.pdf` | PDFBox |
| 4 | POST | `/form/sample` | – | `form-mau.pdf` | PDFBox |
| 4 | POST | `/form/read` | part `file` | JSON `List<FieldInfo>` | PDFBox |
| 4 | POST | `/form/fill` | part `file`, part `values` (JSON), `flatten` | `form-da-dien.pdf` | PDFBox |
| 5 | POST | `/preflight` | part `file` | JSON `PreflightResult` | PDFBox Preflight |
| 6 | POST | `/render` | part `file`, `page`, `dpi`, `format=png\|jpg` | `page-N.png/jpg` | PDFBox |
| 6 | POST | `/render/all` | part `file`, `dpi`, `format` | `pages.zip` | PDFBox |
| 7 | GET | `/print/printers` | – | JSON `List<String>` | Java Print API |
| 7 | POST | `/print` | part `file`, `printer`, `copies` | JSON `{ "printedOn": ... }` | PDFBox + Java Print |
| 8 | POST | `/sign` | part `file`, `reason`, `location`, `visible`, `page`, `x,y,w,h`, `belowText`, part `stamp` | `signed.pdf` | PDFBox + BouncyCastle |
| 8 | POST | `/verify` | part `file` | JSON `List<SignatureCheck>` | PDFBox + BouncyCastle |
| – | POST | `/{type}` | JSON `NotifyRequest` | JSON `NotifyResult` | Strategy |

> `POST /demo/{type}` là path có biến; Spring ưu tiên path tĩnh nên `/demo/create`, `/demo/text`... không bị
> nuốt. Tuy nhiên nếu gọi nhầm một path chưa tồn tại (ví dụ `/demo/crate`) request sẽ rơi vào Strategy và
> báo `No strategy 'crate'`.

---

## 3. Sequence diagram các luồng PDF

### 3.1 Luồng chung cho các API nhận file upload

Hầu hết endpoint POST đều đi theo khuôn này:

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant L as PDFBox Loader
    participant D as PDDocument

    C->>DC: POST /demo/xxx (multipart: file, params)
    DC->>DC: file.getBytes()
    DC->>S: operation(byte[] pdf, params...)
    S->>L: Loader.loadPDF(pdf [, password])
    L-->>S: PDDocument
    S->>D: xử lý (đọc / sửa / render ...)
    alt Kết quả là PDF
        S->>D: save(doc) → ByteArrayOutputStream
    else Kết quả là nhiều file
        S->>S: zip(Map<tên, byte[]>)
    else Kết quả là dữ liệu
        S->>S: tạo record (TextResult, FieldInfo...)
    end
    S->>D: close() (try-with-resources)
    S-->>DC: byte[] / record
    alt byte[]
        DC->>DC: file(body, filename, mediaType)<br/>Content-Disposition: attachment (UTF-8)
        DC-->>C: 200 application/pdf | zip | image
    else record
        DC-->>C: 200 application/json
    end
```

### 3.2 `GET /demo/invoice` — OpenPDF, stream trực tiếp ra response

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant R as HttpServletResponse
    participant OP as OpenPDF Document / PdfWriter

    C->>DC: GET /demo/invoice
    DC->>R: setContentType("application/pdf")<br/>Content-Disposition: attachment; filename=invoice.pdf
    DC->>R: getOutputStream() → BufferedOutputStream
    DC->>OP: new Document()<br/>PdfWriter.getInstance(document, bos)
    DC->>OP: open()
    DC->>OP: add(Paragraph "DUYTRAN.COM")
    DC->>OP: add(Paragraph "Invoice generated at: now")
    DC->>OP: close()
    OP-->>R: ghi byte PDF vào stream
    alt DocumentException
        DC-->>C: IOException("PDF creation failed") → 500
    else OK
        R-->>C: 200 invoice.pdf (chunked, không biết trước độ dài)
    end
```

Ưu điểm: không giữ toàn bộ PDF trong heap. Nhược: lỗi xảy ra giữa chừng khi response đã commit thì client
nhận file hỏng thay vì mã lỗi.

### 3.3 `GET /demo/pdf` — OpenPDF, build trong bộ nhớ

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant OP as OpenPDF

    C->>DC: GET /demo/pdf
    DC->>S: createPDF()
    S->>OP: new Document(A4, lề 50)<br/>PdfWriter.getInstance(doc, ByteArrayOutputStream)
    S->>OP: addTitle / addAuthor / addCreationDate (trước open)
    S->>OP: open()
    S->>OP: add "Trang 1" → newPage() → add "Trang 2"
    S->>OP: close() (finally)
    S-->>DC: byte[]
    DC-->>C: 200 demo.pdf (Content-Length = pdf.length)
```

### 3.4 `POST /demo/create` — Hóa đơn bằng PDFBox (vẽ cấp thấp)

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant D as PDDocument / PDPage
    participant CS as PDPageContentStream
    participant F as Font TTF

    C->>DC: POST /demo/create (customer, logo?)
    DC->>DC: bytes(logo) → null nếu không có
    DC->>S: createInvoice(customer, logo)
    S->>D: new PDDocument() + addPage(A4)
    S->>F: loadFont(doc, subset = true)
    F-->>S: PDType0Font
    S->>CS: new PDPageContentStream(doc, page)
    opt Có logo
        S->>CS: drawImage(logo, giữ tỉ lệ, cao 40pt)
    end
    S->>CS: tiêu đề căn giữa "HÓA ĐƠN GIÁ TRỊ GIA TĂNG"
    S->>CS: Khách hàng, Ngày lập
    S->>CS: kẻ bảng (moveTo/lineTo/stroke)
    loop từng dòng & ô
        S->>CS: text(...) — cột số căn phải
    end
    S->>CS: Tổng tiền, chữ ký 2 bên
    S->>CS: close()
    S->>D: set metadata (Title, Author, CreationDate)
    S->>D: save(doc)
    S-->>DC: byte[]
    DC-->>C: 200 hoa-don.pdf
```

### 3.5 Trích xuất text — `/text` và `/text/area`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant D as PDDocument
    participant TS as PDFTextStripper
    participant TA as PDFTextStripperByArea

    alt POST /demo/text
        C->>DC: file, startPage?, endPage?, sortByPosition, password?
        DC->>S: extractText(bytes, ...)
        S->>D: Loader.loadPDF(bytes [, password])
        S->>TS: setSortByPosition / setStartPage / setEndPage<br/>setPageEnd("--- hết trang ---")
        S->>TS: getText(doc)
        TS-->>S: String
        S-->>DC: TextResult(totalPages, text)
        DC-->>C: 200 JSON
    else POST /demo/text/area
        C->>DC: file, page, x, y, w, h (gốc trên-trái, pt)
        DC->>S: extractTextByArea(bytes, page, x, y, w, h)
        S->>D: Loader.loadPDF(bytes)
        S->>TA: addRegion("vung", Rectangle2D(x, y, w, h))
        S->>TA: extractRegions(doc.getPage(page - 1))
        TA-->>S: getTextForRegion("vung")
        S-->>DC: String
        DC-->>C: 200 {"text": "..."}
    end
```

### 3.6 Tách / gộp — `/split` và `/merge`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant SP as Splitter
    participant M as PDFMergerUtility

    alt POST /demo/split
        C->>DC: file, pagesPerFile | ranges
        DC->>S: split(bytes, pagesPerFile, ranges)
        S->>S: Loader.loadPDF → n trang
        alt có ranges "1-2,3,5-7"
            loop từng khoảng a-b
                S->>S: validate 1 ≤ a ≤ b ≤ n<br/>(sai → IllegalArgumentException)
                S->>SP: setStartPage(a) / setEndPage(b) / setSplitAtPage(b-a+1)
                SP-->>S: PDDocument → save → "trang_a-b.pdf"
            end
        else không có ranges
            S->>SP: setSplitAtPage(pagesPerFile)
            loop từng phần
                SP-->>S: PDDocument → save → "part_001.pdf"...
            end
        end
        S->>S: zip(files)
        S-->>DC: byte[]
        DC-->>C: 200 split.zip
    else POST /demo/merge
        C->>DC: files[] (theo thứ tự)
        DC->>DC: List<byte[]>
        DC->>S: merge(pdfs)
        S->>S: size < 2 → IllegalArgumentException
        loop từng file
            S->>M: addSource(RandomAccessReadBuffer)
        end
        S->>M: setDestinationStream(out)<br/>mergeDocuments(memoryOnlyStreamCache)
        S-->>DC: byte[]
        DC-->>C: 200 merged.pdf
    end
```

### 3.7 Form (AcroForm) — tạo mẫu, đọc, điền

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant A as PDAcroForm
    participant F as Font TTF

    Note over C,F: (1) Tạo form mẫu
    C->>DC: POST /demo/form/sample
    DC->>S: createSampleForm()
    S->>F: loadFont(doc, subset = false)
    S->>A: new PDAcroForm + DefaultResources(font) + DefaultAppearance
    loop 5 field: soHopDong, hoTen, soTien, ngayGiaiNgan, ghiChu
        S->>A: PDTextField + widget (rect, border) → page.annotations
    end
    S-->>DC: byte[]
    DC-->>C: form-mau.pdf

    Note over C,F: (2) Đọc form
    C->>DC: POST /demo/form/read (file)
    DC->>S: readForm(bytes)
    S->>A: getFieldTree() (bỏ PDNonTerminalField)
    S-->>DC: List<FieldInfo(name, type, value, readOnly, required)>
    DC-->>C: JSON

    Note over C,F: (3) Điền form
    C->>DC: POST /demo/form/fill (file, values JSON, flatten)
    DC->>S: fillForm(bytes, values, flatten)
    S->>A: getAcroForm() (null → lỗi "PDF không có AcroForm")
    S->>F: dr.add(loadFont(doc, false)) — font có dấu tiếng Việt
    loop từng (key, value)
        alt PDTextField
            S->>A: setDefaultAppearance(font 0 Tf = auto size) + setValue
        else PDCheckBox
            S->>A: check() / unCheck()
        else combo / list / radio
            S->>A: setValue (phải nằm trong options)
        end
    end
    S->>S: field thiếu → IllegalArgumentException
    opt flatten = true
        S->>A: flatten() — khóa form
    end
    S-->>DC: byte[]
    DC-->>C: form-da-dien.pdf
```

### 3.8 Preflight PDF/A-1b

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant FS as File tạm
    participant PF as PreflightParser

    C->>DC: POST /demo/preflight (file)
    DC->>S: preflight(bytes)
    S->>FS: Files.createTempFile + write(bytes)
    S->>PF: validate(tmp.toFile())
    PF-->>S: ValidationResult
    S->>S: map errors → PreflightError(code, details, page)
    S->>FS: deleteIfExists (finally)
    S-->>DC: PreflightResult(valid, errors)
    DC-->>C: 200 JSON
```

### 3.9 Render ảnh — `/render` và `/render/all`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant R as PDFRenderer
    participant IO as ImageIO

    C->>DC: POST /demo/render (file, page, dpi, format) | /render/all (file, dpi, format)
    DC->>S: renderPage(...) | renderAll(...)
    S->>S: normalizeFormat: png | jpg (khác → lỗi)
    S->>R: new PDFRenderer(Loader.loadPDF(bytes))
    loop 1 trang (render) hoặc mọi trang (render/all)
        S->>R: renderImageWithDPI(index, dpi, RGB)
        R-->>S: BufferedImage
        S->>IO: write(img, png|jpeg) → byte[]
        Note right of S: ghi ngay để không giữ nhiều BufferedImage
    end
    alt render
        S-->>DC: byte[] ảnh
        DC-->>C: page-N.png | page-N.jpg (image/png | image/jpeg)
    else render/all
        S->>S: zip("page_001.png", ...)
        S-->>DC: byte[]
        DC-->>C: pages.zip
    end
```

### 3.10 In — `/print/printers` và `/print`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant PSL as PrintServiceLookup
    participant PJ as PrinterJob

    C->>DC: GET /demo/print/printers
    DC->>S: listPrinters()
    S->>PSL: lookupPrintServices(null, null)
    S-->>DC: List<String>
    DC-->>C: JSON

    C->>DC: POST /demo/print (file, printer?, copies)
    DC->>S: print(bytes, printer, copies)
    alt printer trống
        S->>PSL: lookupDefaultPrintService()
    else có tên
        S->>PSL: tìm theo tên (ignore case)
    end
    S->>S: không thấy → IllegalStateException
    S->>PJ: setPrintService / setPageable(PDFPageable) / setCopies
    S->>PJ: print()
    S-->>DC: tên máy in
    DC-->>C: {"printedOn": "..."}
```

Chỉ hoạt động khi máy chủ có spooler (CUPS / Windows) — không chạy được trong container thông thường.

### 3.11 Ký số và xác thực — `/sign` và `/verify`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant S as PDFServiceImpl
    participant RL as RectLocator
    participant SG as PdfBoxSigner
    participant BC as BouncyCastle CMS

    Note over C,BC: Ký số
    C->>DC: POST /demo/sign (file, reason, location, visible, page, x,y,w,h, belowText, stamp?)
    DC->>S: sign(...)
    alt visible = false
        S->>SG: sign(pdf, reason, location) — ký ẩn
    else visible = true
        alt belowText có giá trị
            S->>RL: belowText(text, w, h, 10)
        else có x, y
            S->>RL: topLeft(x, y, w, h)
        else
            S->>RL: bottomRight(40, 40, w, h)
        end
        S->>S: pageIndex = page < 0 ? page : page - 1 (-1 = trang cuối)
        S->>SG: signVisible(pdf, reason, location, pageIndex, locator, font, stamp)
    end
    SG-->>S: byte[] (incremental save)
    S-->>DC: byte[]
    DC-->>C: signed.pdf

    Note over C,BC: Xác thực
    C->>DC: POST /demo/verify (file)
    DC->>S: verify(bytes)
    loop từng PDSignature
        S->>S: coversWholeFile = br[2] + br[3] == pdf.length
        S->>BC: CMSSignedData(signedContent, contents)
        S->>BC: lấy cert theo SID → si.verify(cert)
        BC-->>S: integrityValid
        S->>S: timestampOf(si) (nếu có TSA)
    end
    S-->>DC: List<SignatureCheck>
    DC-->>C: JSON
```

`verify` chỉ kiểm tra **toàn vẹn** (hash + chữ ký khớp nội dung) và việc chữ ký có phủ hết file hay không.
Chưa kiểm tra chuỗi tin cậy / thu hồi chứng thư (OCSP/CRL) — việc đó nên dùng EU DSS hoặc pyHanko.

---

## 4. Strategy Executor

### 4.1 Khởi động: tự đăng ký `StrategyExecutor` theo generic

```mermaid
sequenceDiagram
    autonumber
    participant SB as Spring Boot
    participant REG as StrategyExecutorRegistrar
    participant BF as BeanFactory / Registry

    SB->>REG: load qua AutoConfiguration.imports
    SB->>REG: postProcessBeanFactory(beanFactory)
    REG->>BF: getBeanNamesForType(Strategy.class)
    loop từng Strategy bean
        REG->>REG: GenericTypeResolver → (T, R)<br/>không resolve được → lỗi
        REG->>REG: gom nhóm theo GenericPair(T, R)
    end
    loop từng GenericPair
        REG->>REG: tên bean = lowerFirst(T.simpleName) + "Executor"<br/>vd: notifyRequestExecutor, voidExecutor
        REG->>REG: kiểm tra trùng tên
        REG->>BF: registerBeanDefinition(StrategyExecutor<T,R>, supplier lazy)
    end
    Note over BF: Khi bean được inject lần đầu:<br/>getBean từng Strategy, re-validate generic sau proxy (AOP),<br/>new StrategyExecutor(name, strategies) — trùng type() → lỗi
```

### 4.2 Runtime: `POST /demo/{type}`

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant DC as DemoController
    participant SE as StrategyExecutor<NotifyRequest, NotifyResult>
    participant NS as NotifyStrategy

    C->>DC: POST /demo/email (JSON NotifyRequest)
    DC->>SE: execute("email", request)
    SE->>SE: normalize → "EMAIL" (trim + upper)
    alt có strategy
        SE->>NS: execute(request)
        NS-->>SE: NotifyResult
        SE-->>DC: NotifyResult
        DC-->>C: 200 JSON
    else không có
        SE-->>DC: IllegalArgumentException("No strategy ... Available: [EMAIL]")
        DC-->>C: 500
    end
```

Thêm kênh mới chỉ cần tạo bean `implements Strategy<NotifyRequest, NotifyResult>` với `type()` riêng — không phải
sửa controller hay executor.

---

## 5. Build & chạy

Yêu cầu: JDK 25.

```bash
./gradlew bootRun
```

Ví dụ gọi API:

```bash
curl -o demo.pdf     http://localhost:8080/demo/pdf
curl -o hoa-don.pdf  -F customer="Công ty ABC" -F logo=@logo.png http://localhost:8080/demo/create
curl -F file=@a.pdf -F startPage=1 -F endPage=2 http://localhost:8080/demo/text
curl -o split.zip    -F file=@a.pdf -F ranges="1-2,3" http://localhost:8080/demo/split
curl -o merged.pdf   -F files=@a.pdf -F files=@b.pdf http://localhost:8080/demo/merge
curl -o filled.pdf   -F file=@form-mau.pdf \
     -F 'values={"hoTen":"Nguyễn Văn A"};type=application/json' -F flatten=true \
     http://localhost:8080/demo/form/fill
curl -o page-1.png   -F file=@a.pdf -F page=1 -F dpi=150 http://localhost:8080/demo/render
```

---

## Trạng thái hiện tại

Code đang ở giữa quá trình chuyển đổi, **chưa compile được**. Những việc cần làm để chạy đủ các luồng trên:

**`DemoController`**
- Thiếu field `StrategyExecutor<NotifyRequest, NotifyResult> strategyExecutor` (đang dùng ở `send`).
- Thiếu hằng `PDF` / `ZIP` (ví dụ `MediaType.APPLICATION_PDF` và `MediaType.parseMediaType("application/zip")`).
- Thiếu import `java.util.List`, `java.util.ArrayList` và các record `TextResult`, `FieldInfo`, `PreflightResult`,
  `SignatureCheck` (đang nằm trong `PDFServiceImpl`).

**`IPDFService` / `PDFServiceImpl`**
- Interface mới có `createPDF()` / `createImagePDF()`; cần khai báo thêm các method controller đang gọi.
- Phần lớn method (mục 2 → 8) và helper `text`, `width`, `money`, `zip`, `normalizeFormat`, `toImageBytes`
  đang bị comment.
- `fontFile()` dùng `props.fontPath()` nhưng `DemoProperties` chưa tồn tại (cần property kiểu `demo.font-path`
  trỏ tới font TTF có dấu tiếng Việt).
- `PdfBoxSigner`, `RectLocator` chưa có.

**Dependency còn thiếu trong `build.gradle.kts`**
- `org.apache.pdfbox:preflight` — cho `/preflight`.
- `org.bouncycastle:bcprov-jdk18on`, `org.bouncycastle:bcpkix-jdk18on` — cho `/sign`, `/verify`.
