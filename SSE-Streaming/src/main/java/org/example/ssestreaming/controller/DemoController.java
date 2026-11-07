package org.example.ssestreaming.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.ssestreaming.common.SseProgressStore;
import org.example.ssestreaming.common.UploadStatus;
import org.example.ssestreaming.service.BatchCheckService;
import org.example.ssestreaming.service.DemoAsyncService;
import org.example.ssestreaming.service.IUploadService;
import org.example.ssestreaming.service.SseEventService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@RestController
@RequestMapping("/demo")
@RequiredArgsConstructor
public class DemoController {
    private final IUploadService uploadService;
    private final SseProgressStore statusStore;
    private final ExecutorService executor;
    private final SseEventService service;
    private final BatchCheckService batchCheckService;

    private final DemoAsyncService demoAsyncService;

    @PostMapping(value = "/jobs/{jobId}/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter stream(@PathVariable String jobId, @RequestBody(required = false) HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-cache");
        response.setHeader("X-Accel-Buffering", "no");   // nginx không buffer

        SseEmitter emitter = new SseEmitter(Duration.ofMinutes(5).toMillis());
        AtomicBoolean cancelled = new AtomicBoolean(false);

        emitter.onCompletion(() -> {
            cancelled.set(true);
            log.info("[{}] completed", jobId);
        });
        emitter.onTimeout(() -> {
            cancelled.set(true);
            log.warn("[{}] timeout", jobId);
            emitter.complete();
        });
        emitter.onError(ex -> {
            cancelled.set(true);
            log.warn("[{}] client disconnected: {}", jobId, ex.getMessage());
        });

        demoAsyncService.runJob(jobId, emitter, cancelled);   // trả về ngay, không block
        return emitter;
    }


    @PostMapping("/upload")
    public ResponseEntity<UploadStatus> upload(@RequestParam("files") MultipartFile files) {
        UploadStatus uploadStatus = uploadService.upLoadFile(files);
        return ResponseEntity.ok(uploadStatus);
    }

    @PostMapping("/multiple-upload")
    public ResponseEntity<UploadStatus> multipleUpload(@RequestParam("files") List<MultipartFile> files) {
        UploadStatus uploadStatus = uploadService.multipleUpload(files);
        return ResponseEntity.ok(uploadStatus);
    }

    @GetMapping(
            value = "/upload/stream",
            produces = MediaType.TEXT_EVENT_STREAM_VALUE
    )
    public SseEmitter stream(@RequestParam("streamId") String streamId) {
        return service.handleUploadProgress(streamId);
    }

    @GetMapping("/status")
    public ResponseEntity<List<BatchCheckService.Account>> getStatus(@RequestParam("uploadId") String uploadId) {
        try {
            List<BatchCheckService.Account> accounts = mock100Accounts();
            batchCheckService.process(accounts);
            System.out.println("====== SUCCESS ======");
            return ResponseEntity.ok(accounts);
        } catch (Exception e) {
            log.error("Error processing batch", e);
            return ResponseEntity.status(500).build();
        }
    }

    private static List<BatchCheckService.Account> mock100Accounts() {
        List<BatchCheckService.Account> accounts = new ArrayList<>();
        for (int i = 1; i <= 10000; i++) {
            accounts.add(new BatchCheckService.Account("ACC_" + i, "Account " + i));
        }
        return accounts;
    }


}
