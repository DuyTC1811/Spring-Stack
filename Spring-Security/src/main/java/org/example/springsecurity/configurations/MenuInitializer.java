package org.example.springsecurity.configurations;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class MenuInitializer implements ApplicationRunner {
    private final RequestMappingHandlerMapping mapping;

    @Override
    public void run(@NonNull ApplicationArguments args) {
        if (!log.isDebugEnabled()) {
            return;
        }
        Map<RequestMappingInfo, HandlerMethod> map = mapping.getHandlerMethods();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : map.entrySet()) {
            log.debug("{} -> {}", entry.getKey(), entry.getValue());
        }
    }
}
