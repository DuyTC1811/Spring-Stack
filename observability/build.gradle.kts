plugins {
    java
    id("org.springframework.boot") version "4.1.2"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"
description = "observability"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // ===== Web & Validation =====
    implementation("org.springframework.boot:spring-boot-starter-webmvc")               // REST API (Spring MVC + embedded Tomcat)
    implementation("org.springframework.boot:spring-boot-starter-validation")           // Bean Validation (@Valid, @NotNull...)
    // ===== Persistence =====
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")             // JPA/Hibernate + HikariCP
    runtimeOnly("org.postgresql:postgresql")                                            // JDBC driver PostgreSQL
    // ===== AOP =====
    implementation("org.springframework.boot:spring-boot-starter-aspectj")              // @Aspect, cũng cần cho @Observed
    // ===== Observability =====
    implementation("org.springframework.boot:spring-boot-starter-actuator")             // health, metrics, ObservationRegistry
    implementation("org.springframework.boot:spring-boot-starter-opentelemetry")        // Micrometer Tracing + OTel bridge + OTLP exporter
    implementation("net.ttddyy.observation:datasource-micrometer-spring-boot:2.3.0")    // span cho mỗi JDBC query
    runtimeOnly("io.micrometer:micrometer-registry-prometheus")                         // cung cấp /actuator/prometheus cho Alloy scrape
    // ===== Lombok =====
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    // ===== Test =====
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-data-jpa-test")
    testImplementation("org.springframework.boot:spring-boot-starter-validation-test")
    testImplementation("org.springframework.boot:spring-boot-starter-actuator-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
