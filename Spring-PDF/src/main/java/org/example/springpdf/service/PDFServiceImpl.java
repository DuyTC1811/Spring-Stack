package org.example.springpdf.service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.multipdf.PDFMergerUtility;
import org.apache.pdfbox.multipdf.Splitter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceCharacteristicsDictionary;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.printing.PDFPageable;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.PDFTextStripperByArea;
import org.openpdf.text.Document;
import org.openpdf.text.PageSize;
import org.openpdf.text.Paragraph;
import org.openpdf.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import javax.print.PrintService;
import javax.print.PrintServiceLookup;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.awt.print.PrinterJob;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class PDFServiceImpl implements IPDFService {
    private static final Locale VI = Locale.forLanguageTag("vi-VN");
    @Override
    public byte[] createPDF() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 50, 50, 50, 50);
        try {
            PdfWriter.getInstance(document, out);

            // Metadata đặt TRƯỚC open()
            document.addTitle("Hóa đơn");
            document.addAuthor("MSB");
            document.addCreationDate();

            document.open();

            document.add(new Paragraph("Xin chào -- Trang 1"));
            document.add(new Paragraph("Đây là file PDF đầu tiên."));

            document.newPage();
            document.add(new Paragraph("Xin chào -- Trang 2"));

            out.close();
        } catch (Exception exp) {
            throw new RuntimeException(exp);
        } finally {
            if (document.isOpen()) {
                document.close();
            }
        }
        return out.toByteArray();
    }



//    private final DemoProperties props;
//    private final PdfBoxSigner signer;

    // =====================================================================
    // 1. TẠO PDF: text tiếng Việt, ảnh, bảng, metadata
    // =====================================================================

    public record Item(String name, int qty, long price) {
    }

    public byte[] createInvoice(String customer, byte[] logo) throws IOException {
        List<Item> items = List.of(
                new Item("Phí chuyển tiền quốc tế", 1, 500_000),
                new Item("Phí điện phí SWIFT", 2, 150_000),
                new Item("Phí kiểm tra chứng từ", 3, 200_000));

        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            PDFont font = loadFont(doc, true);
            float pageW = page.getMediaBox().getWidth();
            float top = page.getMediaBox().getHeight() - 50;

            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                // Logo góc trên-trái (giữ tỉ lệ)
                if (logo != null && logo.length > 0) {
                    PDImageXObject img = PDImageXObject.createFromByteArray(doc, logo, "logo");
                    float h = 40;
                    float w = h * img.getWidth() / img.getHeight();
                    cs.drawImage(img, 50, top - h + 10, w, h);
                }

                String title = "HÓA ĐƠN GIÁ TRỊ GIA TĂNG";
                text(cs, font, 18, (pageW - width(font, 18, title)) / 2, top - 40, title);

                float y = top - 80;
                text(cs, font, 11, 50, y, "Khách hàng: " + customer);
                text(cs, font, 11, 50, y - 18, "Ngày lập: "
                        + new SimpleDateFormat("dd/MM/yyyy").format(Calendar.getInstance().getTime()));

                // Bảng: STT | Nội dung | SL | Đơn giá | Thành tiền
                float[] colX = {50, 85, 330, 375, 465, 545};
                String[] header = {"STT", "Nội dung", "SL", "Đơn giá", "Thành tiền"};
                float rowH = 22;
                float tableTop = y - 45;

                List<String[]> rows = new ArrayList<>();
                long total = 0;
                for (int i = 0; i < items.size(); i++) {
                    Item it = items.get(i);
                    long amount = it.qty() * it.price();
                    total += amount;
                    rows.add(new String[]{String.valueOf(i + 1), it.name(), String.valueOf(it.qty()),
                            money(it.price()), money(amount)});
                }
                rows.addFirst(header);

                cs.setLineWidth(0.7f);
                for (int r = 0; r <= rows.size(); r++) {              // kẻ ngang
                    float ly = tableTop - r * rowH;
                    cs.moveTo(colX[0], ly);
                    cs.lineTo(colX[colX.length - 1], ly);
                }
                float tableBottom = tableTop - rows.size() * rowH;
                for (float x : colX) {                                  // kẻ dọc
                    cs.moveTo(x, tableTop);
                    cs.lineTo(x, tableBottom);
                }
                cs.stroke();

                for (int r = 0; r < rows.size(); r++) {
                    float ty = tableTop - r * rowH - 15;
                    String[] cells = rows.get(r);
                    for (int c = 0; c < cells.length; c++) {
                        boolean rightAlign = r > 0 && c >= 2;          // số căn phải
                        float tx = rightAlign
                                ? colX[c + 1] - 4 - width(font, 10, cells[c])
                                : colX[c] + 4;
                        text(cs, font, 10, tx, ty, cells[c]);
                    }
                }

                String totalLine = "Tổng tiền thanh toán: " + money(total) + " VND";
                text(cs, font, 12, colX[colX.length - 1] - width(font, 12, totalLine), tableBottom - 25, totalLine);

                text(cs, font, 11, 80, tableBottom - 90, "NGƯỜI MUA HÀNG");
                text(cs, font, 11, 380, tableBottom - 90, "ĐẠI DIỆN BÊN BÁN");
            }

            PDDocumentInformation info = doc.getDocumentInformation();
            info.setTitle("Hóa đơn demo");
            info.setAuthor("MSB PDFBox demo");
            info.setCreationDate(Calendar.getInstance());
            return save(doc);
        }
    }

    // =====================================================================
    // 2. TRÍCH XUẤT TEXT
    // =====================================================================

//    public record TextResult(int totalPages, String text) {
//    }
//
//    public TextResult extractText(byte[] pdf, Integer startPage, Integer endPage,
//                                  boolean sortByPosition, String password) throws IOException {
//        try (PDDocument doc = password == null || password.isEmpty()
//                ? Loader.loadPDF(pdf) : Loader.loadPDF(pdf, password)) {
//            PDFTextStripper stripper = new PDFTextStripper();
//            stripper.setSortByPosition(sortByPosition);   // true cho PDF dạng bảng / nhiều cột
//            stripper.setStartPage(startPage == null ? 1 : startPage);
//            stripper.setEndPage(endPage == null ? doc.getNumberOfPages() : endPage);
//            stripper.setPageEnd("\n--- hết trang ---\n");
//            return new TextResult(doc.getNumberOfPages(), stripper.getText(doc));
//        }
//    }

    /**
     * Trích text trong 1 vùng. Tọa độ vùng: gốc TRÊN-TRÁI, đơn vị point (khác với tọa độ vẽ PDF).
     */
//    public String extractTextByArea(byte[] pdf, int page, float x, float y, float w, float h) throws IOException {
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PDFTextStripperByArea stripper = new PDFTextStripperByArea();
//            stripper.setSortByPosition(true);
//            stripper.addRegion("vung", new Rectangle2D.Float(x, y, w, h));
//            stripper.extractRegions(doc.getPage(page - 1));
//            return stripper.getTextForRegion("vung").trim();
//        }
//    }

    // =====================================================================
    // 3. TÁCH / GỘP FILE
    // =====================================================================

    /**
     * ranges = "1-2,3,5-7" -> mỗi khoảng 1 file; bỏ trống -> cắt đều mỗi pagesPerFile trang. Trả về ZIP.
     */
//    public byte[] split(byte[] pdf, int pagesPerFile, String ranges) throws IOException {
//        Map<String, byte[]> files = new LinkedHashMap<>();
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            int n = doc.getNumberOfPages();
//            if (ranges != null && !ranges.isBlank()) {
//                for (String r : ranges.split(",")) {
//                    String[] ab = r.trim().split("-");
//                    int a = Integer.parseInt(ab[0].trim());
//                    int b = ab.length > 1 ? Integer.parseInt(ab[1].trim()) : a;
//                    if (a < 1 || b > n || a > b) {
//                        throw new IllegalArgumentException("Khoảng trang không hợp lệ: " + r + " (file có " + n + " trang)");
//                    }
//                    Splitter splitter = new Splitter();
//                    splitter.setStartPage(a);
//                    splitter.setEndPage(b);
//                    splitter.setSplitAtPage(b - a + 1);
//                    for (PDDocument part : splitter.split(doc)) {
//                        try (part) {
//                            files.put("trang_" + a + "-" + b + ".pdf", save(part));
//                        }
//                    }
//                }
//            } else {
//                Splitter splitter = new Splitter();
//                splitter.setSplitAtPage(Math.max(1, pagesPerFile));
//                int i = 1;
//                for (PDDocument part : splitter.split(doc)) {
//                    try (part) {
//                        files.put(String.format("part_%03d.pdf", i++), save(part));
//                    }
//                }
//            }
//        }
//        return zip(files);
//    }

//    public byte[] merge(List<byte[]> pdfs) throws IOException {
//        if (pdfs.size() < 2) {
//            throw new IllegalArgumentException("Cần ít nhất 2 file để gộp");
//        }
//        PDFMergerUtility merger = new PDFMergerUtility();
//        for (byte[] pdf : pdfs) {
//            merger.addSource(new RandomAccessReadBuffer(pdf));
//        }
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        merger.setDestinationStream(out);
//        // File lớn: dùng IOUtils.createTempFileOnlyStreamCache() để đệm ra đĩa thay vì heap
//        merger.mergeDocuments(IOUtils.createMemoryOnlyStreamCache());
//        return out.toByteArray();
//    }

    // =====================================================================
    // 4. FORM (AcroForm): tạo form mẫu, đọc, điền, flatten
    // =====================================================================

    /**
     * Tạo form "Đơn đề nghị giải ngân" có các field text để test đọc/điền.
     */
//    public byte[] createSampleForm() throws IOException {
//        try (PDDocument doc = new PDDocument()) {
//            PDPage page = new PDPage(PDRectangle.A4);
//            doc.addPage(page);
//
//            PDFont font = loadFont(doc, false); // form: nhúng full font, không subset
//            PDAcroForm acro = new PDAcroForm(doc);
//            doc.getDocumentCatalog().setAcroForm(acro);
//            PDResources dr = new PDResources();
//            COSName fontName = dr.add(font);
//            acro.setDefaultResources(dr);
//            String da = "/" + fontName.getName() + " 11 Tf 0 g";
//            acro.setDefaultAppearance(da);
//
//            String[][] fields = {
//                    {"soHopDong", "Số hợp đồng"},
//                    {"hoTen", "Họ tên khách hàng"},
//                    {"soTien", "Số tiền giải ngân"},
//                    {"ngayGiaiNgan", "Ngày giải ngân"},
//                    {"ghiChu", "Ghi chú"}};
//
//            float top = page.getMediaBox().getHeight() - 60;
//            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
//                text(cs, font, 16, 170, top, "ĐƠN ĐỀ NGHỊ GIẢI NGÂN");
//                for (int i = 0; i < fields.length; i++) {
//                    text(cs, font, 11, 50, top - 60 - i * 40, fields[i][1] + ":");
//                }
//            }
//
//            for (int i = 0; i < fields.length; i++) {
//                PDTextField tf = new PDTextField(acro);
//                tf.setPartialName(fields[i][0]);
//                tf.setDefaultAppearance(da);
//                acro.getFields().add(tf);
//
//                PDAnnotationWidget widget = tf.getWidgets().getFirst();
//                widget.setRectangle(new PDRectangle(180, top - 66 - i * 40, 360, 20));
//                widget.setPage(page);
//                widget.setPrinted(true);
//                PDAppearanceCharacteristicsDictionary mk =
//                        new PDAppearanceCharacteristicsDictionary(new org.apache.pdfbox.cos.COSDictionary());
//                mk.setBorderColour(new PDColor(new float[]{0.3f, 0.3f, 0.3f}, PDDeviceRGB.INSTANCE));
//                widget.setAppearanceCharacteristics(mk);
//                page.getAnnotations().add(widget);
//
//                tf.setValue(""); // sinh appearance stream rỗng
//            }
//            return save(doc);
//        }
//    }

//    public record FieldInfo(String name, String type, String value, boolean readOnly, boolean required) {
//    }
//
//    public List<FieldInfo> readForm(byte[] pdf) throws IOException {
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PDAcroForm acro = doc.getDocumentCatalog().getAcroForm();
//            if (acro == null) {
//                return List.of();
//            }
//            List<FieldInfo> result = new ArrayList<>();
//            for (PDField f : acro.getFieldTree()) {      // duyệt cả field lồng nhau
//                if (f instanceof PDNonTerminalField) {
//                    continue;
//                }
//                result.add(new FieldInfo(f.getFullyQualifiedName(), f.getClass().getSimpleName(),
//                        f.getValueAsString(), f.isReadOnly(), f.isRequired()));
//            }
//            return result;
//        }
//    }

    /**
     * values: tên field -> giá trị. flatten = true: biến field thành nội dung tĩnh, không sửa được nữa.
     */
//    public byte[] fillForm(byte[] pdf, Map<String, String> values, boolean flatten) throws IOException {
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PDAcroForm acro = doc.getDocumentCatalog().getAcroForm();
//            if (acro == null) {
//                throw new IllegalArgumentException("PDF không có AcroForm");
//            }
//
//            // Font gốc của form thường là Helvetica -> không có dấu tiếng Việt. Gắn font TTF vào form.
//            PDResources dr = acro.getDefaultResources();
//            if (dr == null) {
//                dr = new PDResources();
//                acro.setDefaultResources(dr);
//            }
//            COSName fontName = dr.add(loadFont(doc, false));
//
//            List<String> missing = new ArrayList<>();
//            for (Map.Entry<String, String> e : values.entrySet()) {
//                PDField field = acro.getField(e.getKey());
//                if (field == null) {
//                    missing.add(e.getKey());
//                    continue;
//                }
//                if (field instanceof PDTextField tf) {
//                    tf.setDefaultAppearance("/" + fontName.getName() + " 0 Tf 0 g"); // 0 = tự co cỡ chữ
//                    tf.setValue(e.getValue());
//                } else if (field instanceof PDCheckBox cb) {
//                    if (Boolean.parseBoolean(e.getValue())) cb.check();
//                    else cb.unCheck();
//                } else {
//                    field.setValue(e.getValue()); // combo/list/radio: giá trị phải nằm trong options
//                }
//            }
//            if (!missing.isEmpty()) {
//                throw new IllegalArgumentException("Không có field: " + missing);
//            }
//            if (flatten) {
//                acro.flatten();
//            }
//            return save(doc);
//        }
//    }

    // =====================================================================
    // 5. PREFLIGHT: kiểm tra chuẩn PDF/A-1b
    // =====================================================================

//    public record PreflightError(String code, String details, Integer page) {
//    }
//
//    public record PreflightResult(boolean valid, List<PreflightError> errors) {
//    }
//
//    public PreflightResult preflight(byte[] pdf) throws IOException {
//        Path tmp = Files.createTempFile("preflight-", ".pdf");   // PreflightParser cần File
//        try {
//            Files.write(tmp, pdf);
//            ValidationResult vr = PreflightParser.validate(tmp.toFile());
//            List<PreflightError> errors = vr.getErrorsList().stream()
//                    .map(e -> new PreflightError(e.getErrorCode(), e.getDetails(), e.getPageNumber()))
//                    .toList();
//            return new PreflightResult(vr.isValid(), errors);
//        } finally {
//            Files.deleteIfExists(tmp);
//        }
//    }

    // =====================================================================
    // 6. RENDER ẢNH: PNG / JPEG
    // =====================================================================

//    public byte[] renderPage(byte[] pdf, int page, float dpi, String format) throws IOException {
//        String fmt = normalizeFormat(format);
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PDFRenderer renderer = new PDFRenderer(doc);
//            BufferedImage img = renderer.renderImageWithDPI(page - 1, dpi, ImageType.RGB);
//            return toImageBytes(img, fmt);
//        }
//    }

    /**
     * Render toàn bộ trang, trả ZIP. Mỗi trang render xong ghi luôn để không giữ nhiều BufferedImage.
     */
//    public byte[] renderAll(byte[] pdf, float dpi, String format) throws IOException {
//        String fmt = normalizeFormat(format);
//        Map<String, byte[]> files = new LinkedHashMap<>();
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PDFRenderer renderer = new PDFRenderer(doc);
//            for (int i = 0; i < doc.getNumberOfPages(); i++) {
//                BufferedImage img = renderer.renderImageWithDPI(i, dpi, ImageType.RGB);
//                files.put(String.format("page_%03d.%s", i + 1, fmt), toImageBytes(img, fmt));
//            }
//        }
//        return zip(files);
//    }

    // =====================================================================
    // 7. IN (Java Printing API) — chỉ chạy khi máy chủ có máy in (CUPS / Windows spooler)
    // =====================================================================

//    public List<String> listPrinters() {
//        return Arrays.stream(PrintServiceLookup.lookupPrintServices(null, null))
//                .map(PrintService::getName)
//                .toList();
//    }

//    public String print(byte[] pdf, String printerName, int copies) throws Exception {
//        PrintService service = (printerName == null || printerName.isBlank())
//                ? PrintServiceLookup.lookupDefaultPrintService()
//                : Arrays.stream(PrintServiceLookup.lookupPrintServices(null, null))
//                .filter(s -> s.getName().equalsIgnoreCase(printerName))
//                .findFirst().orElse(null);
//        if (service == null) {
//            throw new IllegalStateException("Không tìm thấy máy in"
//                    + (printerName == null ? " mặc định" : ": " + printerName));
//        }
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            PrinterJob job = PrinterJob.getPrinterJob();
//            job.setPrintService(service);
//            job.setPageable(new PDFPageable(doc));
//            job.setCopies(Math.max(1, copies));
//            job.setJobName("pdfbox-demo");
//            job.print();
//        }
//        return service.getName();
//    }

    // =====================================================================
    // 8. KÝ SỐ + XÁC THỰC CHỮ KÝ
    // =====================================================================

//    public byte[] sign(byte[] pdf, String reason, String location, boolean visible,
//                       int page, Float x, Float y, Float w, Float h,
//                       String belowText, byte[] stamp) throws IOException {
//        if (!visible) {
//            return signer.sign(pdf, reason, location);
//        }
//        float fw = w == null ? 200 : w;
//        float fh = h == null ? 60 : h;
//        RectLocator locator;
//        if (belowText != null && !belowText.isBlank()) {
//            locator = RectLocator.belowText(belowText, fw, fh, 10);
//        } else if (x != null && y != null) {
//            locator = RectLocator.topLeft(x, y, fw, fh);      // tọa độ kiểu UI: gốc trên-trái
//        } else {
//            locator = RectLocator.bottomRight(40, 40, fw, fh);
//        }
//        int pageIndex = page < 0 ? page : page - 1;           // API 1-based, -1 = trang cuối
//        return signer.signVisible(pdf, reason, location, pageIndex, locator, fontFile(), stamp);
//    }
//
//    public record SignatureCheck(int index, String name, String reason, String location, String signDate,
//                                 String subFilter, String signerSubject, boolean integrityValid,
//                                 boolean coversWholeFile, String timestamp, String error) {
//    }

    /**
     * Kiểm tra TOÀN VẸN (hash + chữ ký khớp với nội dung). Chưa kiểm tra chuỗi tin cậy / thu hồi
     * chứng thư — việc đó nên dùng EU DSS hoặc pyHanko.
     */
//    @SuppressWarnings("unchecked")
//    public List<SignatureCheck> verify(byte[] pdf) throws IOException {
//        List<SignatureCheck> result = new ArrayList<>();
//        try (PDDocument doc = Loader.loadPDF(pdf)) {
//            int idx = 0;
//            for (PDSignature sig : doc.getSignatureDictionaries()) {
//                idx++;
//                String date = sig.getSignDate() == null ? null
//                        : new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(sig.getSignDate().getTime());
//                int[] br = sig.getByteRange();
//                // Chữ ký cuối cùng phải phủ tới hết file; nếu không -> có nội dung được thêm sau khi ký
//                boolean coversWholeFile = br != null && br.length == 4 && br[2] + br[3] == pdf.length;
//                try {
//                    byte[] contents = sig.getContents();
//                    byte[] signedContent = sig.getSignedContent(pdf);
//                    CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signedContent), contents);
//                    SignerInformation si = cms.getSignerInfos().getSigners().iterator().next();
//                    Collection<X509CertificateHolder> certs =
//                            cms.getCertificates().getMatches((Selector<X509CertificateHolder>) si.getSID());
//                    X509CertificateHolder cert = certs.iterator().next();
//                    boolean ok = si.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
//
//                    result.add(new SignatureCheck(idx, sig.getName(), sig.getReason(), sig.getLocation(), date,
//                            sig.getSubFilter(), cert.getSubject().toString(), ok, coversWholeFile,
//                            timestampOf(si), null));
//                } catch (Exception e) {
//                    result.add(new SignatureCheck(idx, sig.getName(), sig.getReason(), sig.getLocation(), date,
//                            sig.getSubFilter(), null, false, coversWholeFile, null, e.getMessage()));
//                }
//            }
//        }
//        return result;
//    }
//
//    private static String timestampOf(SignerInformation si) throws Exception {
//        AttributeTable unsigned = si.getUnsignedAttributes();
//        if (unsigned == null) {
//            return null;
//        }
//        Attribute attr = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
//        if (attr == null) {
//            return null;
//        }
//        TimeStampToken tst = new TimeStampToken(
//                new CMSSignedData(attr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded()));
//        return tst.getTimeStampInfo().getGenTime().toInstant().toString();
//    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private File fontFile() {
        File f = new File(props.fontPath());
        if (!f.isFile()) {
            throw new IllegalStateException("Không thấy font tại demo.font-path = " + props.fontPath());
        }
        return f;
    }

    /**
     * subset = true: chỉ nhúng glyph dùng tới (file nhỏ). Form cần subset = false.
     */
    private PDFont loadFont(PDDocument doc, boolean subset) throws IOException {
        try (InputStream in = new FileInputStream(fontFile())) {
            return PDType0Font.load(doc, in, subset);
        }
    }

//    private static void text(PDPageContentStream cs, PDFont font, float size, float x, float y, String s)
//            throws IOException {
//        cs.beginText();
//        cs.setFont(font, size);
//        cs.newLineAtOffset(x, y);
//        cs.showText(s);
//        cs.endText();
//    }
//
//    private static float width(PDFont font, float size, String s) throws IOException {
//        return font.getStringWidth(s) / 1000f * size;
//    }
//
//    private static String money(long v) {
//        return String.format(VI, "%,d", v);
//    }
//
    private static byte[] save(PDDocument doc) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            doc.save(out);
            doc.close();
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
//
//    private static String normalizeFormat(String format) {
//        String f = format == null ? "png" : format.toLowerCase(Locale.ROOT);
//        if (f.equals("jpeg")) f = "jpg";
//        if (!f.equals("png") && !f.equals("jpg")) {
//            throw new IllegalArgumentException("format chỉ nhận png | jpg");
//        }
//        return f;
//    }
//
//    private static byte[] toImageBytes(BufferedImage img, String fmt) throws IOException {
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        ImageIO.write(img, fmt.equals("jpg") ? "jpeg" : "png", out);
//        return out.toByteArray();
//    }
//
//    private static byte[] zip(Map<String, byte[]> files) throws IOException {
//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
//            for (Map.Entry<String, byte[]> e : files.entrySet()) {
//                zos.putNextEntry(new ZipEntry(e.getKey()));
//                zos.write(e.getValue());
//                zos.closeEntry();
//            }
//        }
//        return bos.toByteArray();
//    }


    @Override
    public void createImagePDF(String inImageFilename, String outFilename) {

    }
}
