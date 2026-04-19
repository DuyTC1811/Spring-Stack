package org.example.springsecurity.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class UpdatePasswordReq {
    @NotBlank(message = "newPassword không được để trống")
    @Size(min = 8, max = 200, message = "newPassword tối thiểu 8 ký tự")
    private String newPassword;

    @NotBlank(message = "passwordOld không được để trống")
    private String passwordOld;
}
