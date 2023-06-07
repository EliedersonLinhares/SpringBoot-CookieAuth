package com.esl.springbootlogin.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequestRecord(
        @NotBlank(message = "Preenchimento obrigatorio") @Email(message = "Email inválido") String email,
        @NotBlank(message = "Preenchimento obrigatorio") String password) {

}
