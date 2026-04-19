package org.example.springsecurity.requests;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import static org.example.springsecurity.utils.RegexUtil.REGEX_EMAIL;
import static org.example.springsecurity.utils.RegexUtil.REGEX_PHONE_NUMBER;
import static org.example.springsecurity.utils.RegexUtil.REGEX_USERNAME;


@Getter
@Setter
public class SignupReq {
    @Hidden
    private String uuid;

    @NotBlank(message = "username không được để trống")
    @Size(min = 3, max = 50, message = "username từ 3 đến 50 ký tự")
    @Schema(description = "Tài khoản user", example = "duytc")
    @Pattern(regexp = REGEX_USERNAME, message = "Không chứa ký tự đặc biệt")
    private String username;

    @NotBlank(message = "password không được để trống")
    @Size(min = 8, max = 200, message = "password tối thiểu 8 ký tự")
    @Schema(description = "Password", example = "duytc1234")
    private String password;

    @NotBlank(message = "confirmPassword không được để trống")
    @Schema(description = "Confirm Password", example = "duytc1234")
    private String confirmPassword;

    @NotBlank(message = "số điện thoại không được để trống")
    @Schema(description = "Số điện thoại", example = "0902288686")
    @Pattern(regexp = REGEX_PHONE_NUMBER, message = "Số điện thoại không hợp lệ.")
    private String mobile;

    @NotBlank(message = "email không được để trống")
    @Schema(description = "Địa chỉ email", example = "duytc@gmail.com")
    @Pattern(regexp = REGEX_EMAIL, message = "Email không hợp lệ")
    private String email;
}
