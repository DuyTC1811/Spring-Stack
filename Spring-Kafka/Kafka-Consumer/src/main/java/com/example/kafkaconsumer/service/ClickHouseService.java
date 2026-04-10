package com.example.kafkaconsumer.service;

import com.clickhouse.client.api.Client;
import com.clickhouse.client.api.metrics.ServerMetrics;
import com.clickhouse.client.api.query.GenericRecord;
import com.clickhouse.client.api.query.QueryResponse;
import com.clickhouse.data.ClickHouseFormat;
import com.example.kafkaconsumer.entity.UserDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClickHouseService {
    private final Client client;
    private static final DateTimeFormatter DT_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Serialize sang RowBinaryWithDefaults
     * <p>
     * Thứ tự cột phải khớp CREATE TABLE:
     *   1. id         UInt64
     *   2. username   String
     *   3. email      String
     *   4. full_name  String
     *   5. is_active  UInt8   DEFAULT 1
     *   6. created_at DateTime DEFAULT now()
     * <p>
     * Mỗi cột có 1 byte flag trước:
     *   0 = giá trị do client cung cấp (đọc tiếp data)
     *   1 = dùng server DEFAULT (không có data phía sau)
     */
    /**
     * Serialize 1 record duy nhất
     */
    public static byte[] serialize(UserDTO u) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream(80)) {
            // id
            out.write(0);
            writeUInt64(out, u.getId());

            // username
            out.write(0);
            writeString(out, u.getUsername());

            // email
            out.write(0);
            writeString(out, u.getEmail());

            // full_name
            out.write(0);
            writeString(out, u.getFullName());

            // is_active (boolean → UInt8: true=1, false=0)
            if (u.getIsActive() != null) {
                out.write(0);
                out.write(u.getIsActive() ? 1 : 0);
            } else {
                out.write(1); // DEFAULT
            }

            // created_at (epoch microseconds → DateTime = epoch seconds UInt32)
            if (u.getCreatedAt() != null) {
                out.write(0);
                long epochSeconds = u.getCreatedAt() / 1_000_000; // micros → seconds
                writeUInt32(out, (int) epochSeconds);
            } else {
                out.write(1); // DEFAULT now()
            }

            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("RowBinary serialization failed", e);
        }
    }

    // Thêm method writeUInt32
    private static void writeUInt32(ByteArrayOutputStream out, int value) {
        byte[] buf = new byte[4];
        ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        out.write(buf, 0, 4);
    }

    /**
     * Thực thi DDL / command (CREATE TABLE, ALTER, DROP, ...)
     */
    public void execute(String sql) {
        try (QueryResponse response = client.query(sql).get()) {
            log.info("Executed: {} | rows read: {}", sql, response.getMetrics().getMetric(ServerMetrics.valueOf("result_rows")));
        } catch (Exception e) {
            throw new RuntimeException("Failed to execute: " + sql, e);
        }
    }

    /**
     * Query trả về danh sách GenericRecord
     */
    public List<GenericRecord> queryAll(String sql) {
        try {
            return client.queryAll(sql);
        } catch (Exception e) {
            throw new RuntimeException("Failed to query: " + sql, e);
        }
    }

    /**
     * Insert dữ liệu dạng CSV string
     */
    public void insertCsv(String tableName, String csvData) {
        try (var inputStream = new ByteArrayInputStream(csvData.getBytes(StandardCharsets.UTF_8))) {
            client.insert(tableName, inputStream, ClickHouseFormat.CSV).get();
            log.info("Inserted CSV data into {}", tableName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to insert CSV into " + tableName, e);
        }
    }

    /**
     * Insert dữ liệu dạng JSONEachRow
     */
    public void insertJson(String tableName, String jsonData) {
        try (var inputStream = new ByteArrayInputStream(jsonData.getBytes(StandardCharsets.UTF_8))) {
            client.insert(tableName, inputStream, ClickHouseFormat.JSONEachRow).get();
            log.info("Inserted JSON data into {}", tableName);
        } catch (Exception e) {
            throw new RuntimeException("Failed to insert JSON into " + tableName, e);
        }
    }

    private static void writeUInt64(ByteArrayOutputStream out, long value) {
        byte[] buf = new byte[8];
        ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).putLong(value);
        out.write(buf, 0, 8);
    }

    private static void writeString(ByteArrayOutputStream out, String value) throws IOException {
        if (value == null) value = "";
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeVarInt(out, bytes.length);
        out.write(bytes);
    }

    private static void writeDateTime(ByteArrayOutputStream out, String dateTimeStr) {
        long epoch = LocalDateTime.parse(dateTimeStr, DT_FMT)
                .toEpochSecond(ZoneOffset.UTC);
        byte[] buf = new byte[4];
        ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).putInt((int) epoch);
        out.write(buf, 0, 4);
    }

    private static void writeVarInt(ByteArrayOutputStream out, int value) {
        while ((value & ~0x7F) != 0) {
            out.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write(value);
    }
}
