package com.example.libreoffice.payload.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

public record OfficeCallback(
        String key,                 // document.key (= editor_key) của phiên
        int status,                 // 1,2,3,4,6,7
        String url,                 // link tải file đã sửa (status 2, 3, 6, 7)
        String changesurl,          // file zip lịch sử thay đổi (dùng cho version history)
        String filetype,            // định dạng của file tại url, VD "docx"
        Integer forcesavetype,      // 0: API, 1: nút Save, 2: timer, 3: submit form (chỉ status 6/7)
        List<String> users,         // user đang mở / user đã sửa
        List<Action> actions,       // hành động: ai vào, ai ra
        String lastsave,            // thời điểm lưu cuối, ISO-8601
        Boolean notmodified,        // true nếu force save mà không có thay đổi
        String userdata             // dữ liệu tùy ý gửi kèm khi gọi forcesave qua Command API
) {
    /**
     * type: 0 = ngắt kết nối, 1 = kết nối mới, 2 = bấm force save
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Action(int type, String userid) {
    }
}

