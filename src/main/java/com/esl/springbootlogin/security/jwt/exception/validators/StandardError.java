package com.esl.springbootlogin.security.jwt.exception.validators;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class StandardError {
    /*
     * Padronização das mensagens de erro do sistema
     */
    private Long timestamp;
    private Integer status;
    private String error;
    private String path;

}
