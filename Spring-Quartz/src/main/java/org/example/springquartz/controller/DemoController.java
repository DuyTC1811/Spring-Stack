package org.example.springquartz.controller;

import org.example.springquartz.request.ScheduleCreateRequest;
import org.example.springquartz.request.ScheduleUpsertRequest;
import org.example.springquartz.service.IQuartzScheduleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static org.example.springquartz.enums.ScheduleType.CRON;
import static org.example.springquartz.enums.ScheduleType.SIMPLE;

@RestController
@RequestMapping("/demo")
public class DemoController {
    private final IQuartzScheduleService service;

    public DemoController(IQuartzScheduleService service) {
        this.service = service;
    }

    // CREATE
    @PostMapping("/schedules")
    public ResponseEntity<?> create(@RequestBody ScheduleCreateRequest req) {
        if (CRON.equals(req.scheduleType())) {
            service.cronSchedule(req); // chỉ tạo mới, tồn tại thì 409
            return ResponseEntity.status(201).build();
        }
        if (SIMPLE.equals(req.scheduleType())) {
            service.simpleSchedule(req); // chỉ tạo mới, tồn tại thì 409
            return ResponseEntity.status(201).build();
        }
        return ResponseEntity.status(400).build();
    }

    // UPDATE (full replace)
    @PutMapping("/schedules/{triggerGroup}/{triggerName}")
    public ResponseEntity<?> update(
            @PathVariable String triggerGroup,
            @PathVariable String triggerName,
            @RequestBody ScheduleUpsertRequest req
    ) {
        service.updateCronSchedule(triggerGroup, triggerName, req);
        return ResponseEntity.ok().build();
    }

    // Command endpoints (giữ như bạn)
    @PostMapping("/triggers/{group}/{name}/pause")
    public ResponseEntity<?> pause(@PathVariable String group, @PathVariable String name) {
        service.pause(name, group);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/triggers/{group}/{name}/resume")
    public ResponseEntity<?> resume(@PathVariable String group, @PathVariable String name) {
        service.resume(name, group);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/jobs/{group}/{name}")
    public ResponseEntity<?> deleteJob(@PathVariable String group, @PathVariable String name) {
        service.deleteJob(name, group);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/detect")
    public ResponseEntity<?> demo(@RequestHeader(value = "User-Agent", required = false) String userAgent) {
        String source = detectSource(userAgent);

        return ResponseEntity.ok(Map.of(
                "source", source,
                "userAgent", userAgent
        ));
    }

    private String detectSource(String ua) {
        if (ua == null || ua.isBlank()) return "UNKNOWN";

        String lower = ua.toLowerCase();

        // ===== BOT =====
        if (lower.contains("bot") || lower.contains("spider") || lower.contains("crawler")) {
            return "BOT";
        }

        // ===== TOOL =====
        if (lower.contains("postman")) return "POSTMAN";
        if (lower.contains("insomnia")) return "INSOMNIA";
        if (lower.contains("curl")) return "CURL";
        if (lower.contains("httpie")) return "HTTPIE";
        if (lower.contains("jmeter")) return "JMETER";
        if (lower.contains("k6")) return "K6";

        // ===== BACKEND CLIENT =====
        if (lower.contains("feign")) return "FEIGN_CLIENT";
        if (lower.contains("okhttp") && lower.contains("react")) return "REACT_NATIVE";
        if (lower.contains("okhttp")) return "ANDROID_APP";
        if (lower.contains("cfnetwork") || lower.contains("darwin")) return "IOS_APP";
        if (lower.contains("dart")) return "FLUTTER_APP";
        if (lower.contains("python-requests")) return "PYTHON";
        if (lower.contains("go-http-client")) return "GO_CLIENT";
        if (lower.contains("axios") || lower.contains("node")) return "NODEJS";
        if (lower.matches(".*(java|jdk|httpclient).*")) return "JAVA_CLIENT";

        // ===== MOBILE WEB =====
        if (lower.contains("iphone")) return "MOBILE_WEB_IOS";
        if (lower.contains("ipad")) return "TABLET_IOS";
        if (lower.contains("android") && lower.contains("mobile")) return "MOBILE_WEB_ANDROID";
        if (lower.contains("android")) return "TABLET_ANDROID";

        // ===== DESKTOP WEB =====
        if (lower.contains("edg/")) return "WEB_EDGE";
        if (lower.contains("chrome")) return "WEB_CHROME";
        if (lower.contains("firefox")) return "WEB_FIREFOX";
        if (lower.contains("safari")) return "WEB_SAFARI";

        return "UNKNOWN";
    }

}
