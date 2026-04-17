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

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

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
        String source = detectSource(userAgent).name();

        return ResponseEntity.ok(Map.of(
                "source", source,
                "userAgent", userAgent
        ));
    }

    public enum Source {
        UNKNOWN,
        BOT,
        // Testing tools
        POSTMAN, INSOMNIA, CURL, HTTPIE, JMETER, K6,
        // HTTP client libraries
        FEIGN_CLIENT, OKHTTP_CLIENT, PYTHON_CLIENT, GO_CLIENT,
        NODE_CLIENT, JAVA_CLIENT,
        // Native mobile apps
        ANDROID_APP, IOS_APP, FLUTTER_APP, REACT_NATIVE,
        // Mobile/Tablet web
        MOBILE_WEB_IOS, MOBILE_WEB_ANDROID,
        TABLET_IOS, TABLET_ANDROID,
        // Desktop browsers
        WEB_EDGE, WEB_CHROME, WEB_FIREFOX, WEB_SAFARI, WEB_OPERA
    }

    // Pre-compile regex cho performance
    private static final Pattern BOT_PATTERN =
            Pattern.compile(".*\\b(bot|spider|crawler|slurp|bingpreview|facebookexternalhit)\\b.*");

    // Rule = điều kiện match + source trả về. Thứ tự QUAN TRỌNG.
    private record Rule(Predicate<String> match, Source source) {
    }

    private static final List<Rule> RULES = List.of(
            // ===== BOT (ưu tiên cao nhất) =====
            new Rule(ua -> BOT_PATTERN.matcher(ua).matches(), Source.BOT),

            // ===== TESTING TOOLS =====
            new Rule(ua -> ua.contains("postmanruntime") || ua.contains("postman"), Source.POSTMAN),
            new Rule(ua -> ua.contains("insomnia"), Source.INSOMNIA),
            new Rule(ua -> ua.startsWith("curl/"), Source.CURL),
            new Rule(ua -> ua.contains("httpie"), Source.HTTPIE),
            new Rule(ua -> ua.contains("jmeter"), Source.JMETER),
            new Rule(ua -> ua.contains("k6/") || ua.contains("grafanak6"), Source.K6),

            // ===== HTTP CLIENT LIBRARIES (signature rõ ràng) =====
            new Rule(ua -> ua.contains("feign"), Source.FEIGN_CLIENT),
            new Rule(ua -> ua.contains("python-requests")
                    || ua.contains("python-urllib")
                    || ua.contains("aiohttp"), Source.PYTHON_CLIENT),
            new Rule(ua -> ua.contains("go-http-client"), Source.GO_CLIENT),
            new Rule(ua -> ua.contains("axios/")
                    || ua.contains("node-fetch")
                    || ua.contains("got ("), Source.NODE_CLIENT),
            new Rule(ua -> ua.contains("dart/")
                    || ua.contains("dart:io"), Source.FLUTTER_APP),

            // ===== NATIVE MOBILE APP =====
            // React Native: OkHttp + "react" keyword
            new Rule(ua -> ua.contains("okhttp") && ua.contains("react"), Source.REACT_NATIVE),
            // Android native: OkHttp + Dalvik/Android (phân biệt với OkHttp backend)
            new Rule(ua -> ua.contains("okhttp")
                    && (ua.contains("dalvik") || ua.contains("android")), Source.ANDROID_APP),
            // iOS native app
            new Rule(ua -> ua.contains("cfnetwork") || ua.contains("darwin"), Source.IOS_APP),

            // ===== MOBILE / TABLET WEB =====
            // iPad trước iPhone (iPad UA có thể chứa "Mobile")
            new Rule(ua -> ua.contains("ipad"), Source.TABLET_IOS),
            new Rule(ua -> ua.contains("iphone") || ua.contains("ipod"), Source.MOBILE_WEB_IOS),
            new Rule(ua -> ua.contains("android") && ua.contains("mobile"), Source.MOBILE_WEB_ANDROID),
            new Rule(ua -> ua.contains("android"), Source.TABLET_ANDROID),

            // ===== DESKTOP BROWSERS =====
            // Thứ tự quan trọng: Edge/Opera trước Chrome (vì UA có cả "Chrome")
            new Rule(ua -> ua.contains("edg/"), Source.WEB_EDGE),
            new Rule(ua -> ua.contains("opr/") || ua.contains("opera"), Source.WEB_OPERA),
            new Rule(ua -> ua.contains("firefox"), Source.WEB_FIREFOX),
            new Rule(ua -> ua.contains("chrome") || ua.contains("crios"), Source.WEB_CHROME),
            // Safari check cuối (Chrome/Edge UA đều chứa "Safari")
            new Rule(ua -> ua.contains("safari"), Source.WEB_SAFARI),

            // ===== GENERIC HTTP CLIENTS (fallback, check cuối) =====
            // OkHttp nhưng không phải React Native / Android app -> backend
            new Rule(ua -> ua.contains("okhttp"), Source.OKHTTP_CLIENT),
            new Rule(ua -> ua.contains("java/")
                    || ua.contains("jdk/")
                    || ua.contains("apache-httpclient")
                    || ua.contains("jakarta-httpclient"), Source.JAVA_CLIENT)
    );

    public Source detectSource(String ua) {
        if (ua == null || ua.isBlank()) return Source.UNKNOWN;

        String lower = ua.toLowerCase();
        return RULES.stream()
                .filter(r -> r.match().test(lower))
                .findFirst()
                .map(Rule::source)
                .orElse(Source.UNKNOWN);
    }

}
