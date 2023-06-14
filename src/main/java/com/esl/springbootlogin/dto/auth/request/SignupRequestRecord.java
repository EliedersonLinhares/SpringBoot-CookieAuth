package com.esl.springbootlogin.dto.auth.request;

import java.util.Set;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignupRequestRecord(
                @NotBlank(message = "Preenchimento obrigatorio") @Size(min = 3, max = 20) String username,
                @NotBlank(message = "Preenchimento obrigatorio") @Size(max = 50) @Email(message = "Email inválido") String email,
                Set<String> role,
                @NotBlank(message = "Preenchimento obrigatorio") @Size(min = 8, max = 20) @Pattern(regexp = "((?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@%#$]).{8,20})", message = "A senha precisa contar ao menos um numero,ao menos uma letra Maiuscula,e ao menos um caracter especial") String password) {

}
