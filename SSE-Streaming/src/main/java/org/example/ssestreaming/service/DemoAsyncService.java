package org.example.ssestreaming.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@Service
public class DemoAsyncService {

    @Async("virtualThread")
    public void runJob(String jobId, SseEmitter emitter, AtomicBoolean cancelled) {
        try {
            for (int i = 1; i <= 10 && !cancelled.get(); i++) {
                Thread.sleep(200);   // giả lập xử lý: gọi DB, BPM, ...

                emitter.send(SseEmitter.event()
                        .id(String.valueOf(i))
                        .name("progress")
                        .data(Map.of("jobId", jobId, "percent", i * 10), MediaType.APPLICATION_JSON));
            }

            if (!cancelled.get()) {
                emitter.send(SseEmitter.event().name("done").data("[DONE]"));
                emitter.complete();
            }
        } catch (IOException e) {
            // client đã đóng kết nối, ví dụ FE bấm Dừng hoặc chuyển trang. Không phải lỗi thật.
            log.info("[{}] client gone, stop job", jobId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            emitter.completeWithError(e);
        } catch (Exception e) {
            log.error("[{}] job failed", jobId, e);
            try {
                emitter.send(SseEmitter.event().name("error").data(Map.of("message", e.getMessage())));
            } catch (IOException ignored) {
            }
            emitter.completeWithError(e);
        }
    }

    @Async("virtualThread")   // sẽ dùng applicationTaskExecutor
    public void doWorkAsync(String input) {
        long start = System.currentTimeMillis();
        Thread current = Thread.currentThread();
        log.info("[ASYNC-START] threadName={}, isVirtual={}, input={} at {}", current.getName(), current.isVirtual(),
                input,
                start);

        // mô phỏng xử lý
        try {
            Thread.sleep(1000); // chỉ demo, thực tế có thể là đọc file, call API, v.v.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        long end = System.currentTimeMillis();
        long duration = end - start;

//        log.info("[ASYNC-END] threadName={}, isVirtual={}, input={}, duration={} ms",
//                current.getName(),
//                current.isVirtual(),
//                input,
//                duration);
    }
}
