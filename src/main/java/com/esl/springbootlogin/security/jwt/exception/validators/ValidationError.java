package com.esl.springbootlogin.security.jwt.exception.validators;

import java.util.ArrayList;
import java.util.List;

//Subclasse para incluir uma lista com mensagem auxilar para o tipo validator 
public class ValidationError extends StandardError {

    private List<FieldMessage> errors = new ArrayList<>();

    public ValidationError(Long timestamp, Integer status, String error, String path) {
        super(timestamp, status, error, path);

    }

    public List<FieldMessage> getErrors() {
        return errors;
    }

    public void addError(String fieldName, String messagem) {
        errors.add(new FieldMessage(fieldName, messagem));
    }

}
