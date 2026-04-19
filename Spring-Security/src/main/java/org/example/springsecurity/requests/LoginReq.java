package org.example.springsecurity.requests;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginReq {
    @NotBlank(message = "username không được để trống")
    @Size(max = 100, message = "username tối đa 100 ký tự")
    @Schema(description = "username", example = "duytc")
    private String username;

    @NotBlank(message = "password không được để trống")
    @Size(max = 200, message = "password tối đa 200 ký tự")
    @Schema(description = "password", example = "duytc")
    private String password;
}
