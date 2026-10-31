package org.example.springpdf.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springpdf.model.NotifyRequest;
import org.example.springpdf.model.NotifyResult;
import org.example.springpdf.service.IPDFService;
import org.example.springpdf.service.StrategyExecutor;
import org.openpdf.text.Document;
import org.openpdf.text.DocumentException;
import org.openpdf.text.Paragraph;
import org.openpdf.text.pdf.PdfWriter;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/demo")
@RequiredArgsConstructor
public class DemoController {
    private final IPDFService pdfService;

    @GetMapping("/invoice")
    public void createPDF(HttpServletResponse response) throws IOException {
        response.setContentType("application/pdf");
        response.setHeader("Content-Disposition", "attachment; filename=invoice.pdf");

        try (BufferedOutputStream bos = new BufferedOutputStream(response.getOutputStream())) {
            Document document = new Document();
            PdfWriter.getInstance(document, bos);
            document.open();
            document.add(new Paragraph("DUYTRAN.COM"));
            document.add(new Paragraph("Invoice generated at: " + LocalDateTime.now()));
            document.close();
        } catch (DocumentException e) {
            throw new IOException("PDF creation failed", e);
        }
    }

    @GetMapping("/pdf")
    public ResponseEntity<byte[]> getPDF() {
        byte[] pdf = pdfService.createPDF();
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition
                                .attachment()
                                .filename("demo.pdf")
                                .build().toString()
                ).contentLength(pdf.length)
                .body(pdf);

    }

    @PostMapping("/create")
    public ResponseEntity<byte[]> create(
            @RequestParam(defaultValue = "Công ty TNHH ABC") String customer,
            @RequestPart(value = "logo", required = false) MultipartFile logo) throws IOException {
        return file(pdfService.createInvoice(customer, bytes(logo)), "hoa-don.pdf", PDF);
    }

    // ---------------- 2. Trích xuất text ----------------

    @PostMapping("/text")
    public TextResult extractText(
            @RequestPart("file") MultipartFile file,
            @RequestParam(required = false) Integer startPage,
            @RequestParam(required = false) Integer endPage,
            @RequestParam(defaultValue = "true") boolean sortByPosition,
            @RequestParam(required = false) String password) throws IOException {
        return pdfService.extractText(file.getBytes(), startPage, endPage, sortByPosition, password);
    }

    /** Lấy text trong 1 vùng (x, y tính từ góc TRÊN-TRÁI, đơn vị pt). */
    @PostMapping("/text/area")
    public Map<String, String> extractTextByArea(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam float x, @RequestParam float y,
            @RequestParam float w, @RequestParam float h) throws IOException {
        return Map.of("text", pdfService.extractTextByArea(file.getBytes(), page, x, y, w, h));
    }

    // ---------------- 3. Tách / gộp ----------------

    /** ranges="1-2,3" -> mỗi khoảng 1 file; không truyền -> cắt đều pagesPerFile trang. Trả ZIP. */
    @PostMapping("/split")
    public ResponseEntity<byte[]> split(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "1") int pagesPerFile,
            @RequestParam(required = false) String ranges) throws IOException {
        return file(pdfService.split(file.getBytes(), pagesPerFile, ranges), "split.zip", ZIP);
    }

    /** Gộp theo đúng thứ tự file gửi lên. */
    @PostMapping("/merge")
    public ResponseEntity<byte[]> merge(@RequestPart("files") List<MultipartFile> files) throws IOException {
        List<byte[]> pdfs = new ArrayList<>();
        for (MultipartFile f : files) {
            pdfs.add(f.getBytes());
        }
        return file(pdfService.merge(pdfs), "merged.pdf", PDF);
    }

    // ---------------- 4. Form ----------------

    /** Tạo form mẫu "Đơn đề nghị giải ngân" để test đọc / điền. */
    @PostMapping("/form/sample")
    public ResponseEntity<byte[]> sampleForm() throws IOException {
        return file(pdfService.createSampleForm(), "form-mau.pdf", PDF);
    }

    @PostMapping("/form/read")
    public List<FieldInfo> readForm(@RequestPart("file") MultipartFile file) throws IOException {
        return pdfService.readForm(file.getBytes());
    }

    /** values: part JSON {"hoTen":"Nguyễn Văn A", ...}; flatten=true khóa form sau khi điền. */
    @PostMapping("/form/fill")
    public ResponseEntity<byte[]> fillForm(
            @RequestPart("file") MultipartFile file,
            @RequestPart("values") Map<String, String> values,
            @RequestParam(defaultValue = "false") boolean flatten) throws IOException {
        return file(pdfService.fillForm(file.getBytes(), values, flatten), "form-da-dien.pdf", PDF);
    }

    // ---------------- 5. Preflight PDF/A-1b ----------------

    @PostMapping("/preflight")
    public PreflightResult preflight(@RequestPart("file") MultipartFile file) throws IOException {
        return pdfService.preflight(file.getBytes());
    }

    // ---------------- 6. Render ảnh ----------------

    @PostMapping("/render")
    public ResponseEntity<byte[]> render(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "150") float dpi,
            @RequestParam(defaultValue = "png") String format) throws IOException {
        boolean jpg = format.equalsIgnoreCase("jpg") || format.equalsIgnoreCase("jpeg");
        return file(pdfService.renderPage(file.getBytes(), page, dpi, format),
                "page-" + page + (jpg ? ".jpg" : ".png"),
                jpg ? MediaType.IMAGE_JPEG : MediaType.IMAGE_PNG);
    }

    @PostMapping("/render/all")
    public ResponseEntity<byte[]> renderAll(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "100") float dpi,
            @RequestParam(defaultValue = "png") String format) throws IOException {
        return file(pdfService.renderAll(file.getBytes(), dpi, format), "pages.zip", ZIP);
    }

    // ---------------- 7. In ----------------

    @GetMapping("/print/printers")
    public List<String> printers() {
        return pdfService.listPrinters();
    }

    @PostMapping("/print")
    public Map<String, String> print(
            @RequestPart("file") MultipartFile file,
            @RequestParam(required = false) String printer,
            @RequestParam(defaultValue = "1") int copies) throws Exception {
        return Map.of("printedOn", pdfService.print(file.getBytes(), printer, copies));
    }

    // ---------------- 8. Ký số / xác thực ----------------

    /**
     * visible=false: ký ẩn. visible=true: vẽ khung chữ ký, vị trí ưu tiên theo thứ tự
     * belowText -> (x, y gốc trên-trái) -> góc dưới-phải. page=-1 là trang cuối.
     */
    @PostMapping("/sign")
    public ResponseEntity<byte[]> sign(
            @RequestPart("file") MultipartFile file,
            @RequestParam(defaultValue = "Phê duyệt") String reason,
            @RequestParam(defaultValue = "Hà Nội") String location,
            @RequestParam(defaultValue = "true") boolean visible,
            @RequestParam(defaultValue = "-1") int page,
            @RequestParam(required = false) Float x,
            @RequestParam(required = false) Float y,
            @RequestParam(required = false) Float w,
            @RequestParam(required = false) Float h,
            @RequestParam(required = false) String belowText,
            @RequestPart(value = "stamp", required = false) MultipartFile stamp) throws IOException {
        byte[] signed = pdfService.sign(file.getBytes(), reason, location, visible,
                page, x, y, w, h, belowText, bytes(stamp));
        return file(signed, "signed.pdf", PDF);
    }

    @PostMapping("/verify")
    public List<SignatureCheck> verify(@RequestPart("file") MultipartFile file) throws IOException {
        return pdfService.verify(file.getBytes());
    }

    // ---------------- helpers ----------------

    private static byte[] bytes(MultipartFile f) throws IOException {
        return f == null || f.isEmpty() ? null : f.getBytes();
    }

    private static ResponseEntity<byte[]> file(byte[] body, String filename, MediaType type) {
        return ResponseEntity.ok()
                .contentType(type)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename(filename, StandardCharsets.UTF_8).build().toString())
                .body(body);
    }


    @PostMapping("/{type}")
    public NotifyResult send(@PathVariable String type, @RequestBody NotifyRequest request) {
        return strategyExecutor.execute(type, request);
    }
}
