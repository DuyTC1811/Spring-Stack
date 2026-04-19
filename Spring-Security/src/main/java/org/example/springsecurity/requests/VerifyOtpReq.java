package org.example.springsecurity.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifyOtpReq {
    @NotBlank(message = "username không được để trống")
    private String username;

    @NotBlank(message = "otp không được để trống")
    @Size(min = 6, max = 8, message = "otp phải có từ 6 đến 8 ký tự")
    private String otp;
}
