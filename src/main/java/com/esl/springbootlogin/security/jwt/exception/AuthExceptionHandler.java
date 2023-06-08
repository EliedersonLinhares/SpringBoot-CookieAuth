package com.esl.springbootlogin.security.jwt.exception;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.esl.springbootlogin.security.jwt.exception.validators.StandardError;
import com.esl.springbootlogin.security.jwt.exception.validators.ValidationError;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//Criamos a classe AuthEntryPointJwt que implementa AuthenticationEntryPoint
//sobrescrevendo o método commence. Esse método irá se ativar em qualquer
//momento que um usuario não autenciado requisitar um recurso http e um
//AuthenticationException será ativado 
@ControllerAdvice
@Component
public class AuthExceptionHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        /*
         * final Map<String, Object> body = new HashMap<>();
         * 
         * body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
         * body.put("error", "Acesso não authorizado");
         * body.put("message", "Usuário ou senha inválidos");
         * body.put("path", request.getServletPath());
         * 
         */
        ProblemDetail problemDetail = details(request, "Acesso não authorizado", "Usuário ou senha inválidos");

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), problemDetail);

    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ProblemDetail problemDetail = details(request, "Acesso negado", "Usuário sem permissões necessárias");

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), problemDetail);
    }

    private ProblemDetail details(HttpServletRequest request, String title, String detail) {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
        LocalDateTime now = LocalDateTime.now();

        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpServletResponse.SC_UNAUTHORIZED);
        problemDetail.setTitle(title);
        problemDetail.setDetail(detail);
        problemDetail.setType(URI.create(request.getServletPath()));
        problemDetail.setProperty("TimeStamp", dtf.format(now));
        return problemDetail;
    }

    // Tratar erros de validação
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<StandardError> validation(MethodArgumentNotValidException e, HttpServletRequest request) {
        ValidationError err = new ValidationError(System.currentTimeMillis(), HttpStatus.UNPROCESSABLE_ENTITY.value(),
                "Erro de validação", request.getRequestURI());

        /*
         * For para percorrer a lista de erros que tem nessa excessão "e", e para cada
         * erro que estiver adicionar ao array
         */

        for (FieldError x : e.getBindingResult().getFieldErrors()) {
            err.addError(x.getField(), x.getDefaultMessage());
        }

        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(err);

    }

}
