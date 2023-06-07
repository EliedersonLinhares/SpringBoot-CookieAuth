package com.esl.springbootlogin.payload.request;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignupRequestRecord(
                @NotBlank(message = "Preenchimento obrigatorio") @Size(min = 3, max = 20) String username,
                @NotBlank(message = "Preenchimento obrigatorio") @Size(max = 50) @Email(message = "Email inválido") String email,
                Set<String> role,
                @NotBlank(message = "Preenchimento obrigatorio") @Size(min = 6, max = 40) String password) {

}
