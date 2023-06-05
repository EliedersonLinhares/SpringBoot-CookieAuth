package com.esl.springbootlogin.security.jwt;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;

//Criamos a classe uthEntryPointJwt que implementa AuthenticationEntryPoint
//sobrescrevendo o método commence. Esse método irá se ativar em qualquer
//momento que um usuario não autenciado requisitar um recurso http e um
//AuthenticationException será ativado 
@ControllerAdvice
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());
        // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error:
        // Unauthorized");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String, Object> body = new HashMap<>();

        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", "Usuário ou senha inválidos");
        body.put("path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        // logger.error("AccessDenied error: {}", accessDeniedException.getMessage());
        // httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
        // httpServletResponse.getWriter().write(convertObjectToJson(new
        // ErrorResponse(ResponseMessages.NOT_PERMITTED)));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        final Map<String, Object> body = new HashMap<>();

        body.put("status", HttpServletResponse.SC_FORBIDDEN);
        body.put("error", "AccessDenied");
        body.put("message", "Usuario sem permissões nescessarias");
        body.put("path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }

    /*
     * @ExceptionHandler(value = { InternalServerError.class })
     * public void commence(HttpServletRequest request, HttpServletResponse
     * response,
     * InternalServerError internalServerError) throws IOException {
     * // logger.error("AccessDenied error: {}",
     * accessDeniedException.getMessage());
     * // httpServletResponse.setStatus(HttpStatus.FORBIDDEN.value());
     * // httpServletResponse.getWriter().write(convertObjectToJson(new
     * // ErrorResponse(ResponseMessages.NOT_PERMITTED)));
     * response.setContentType(MediaType.APPLICATION_JSON_VALUE);
     * response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
     * 
     * final Map<String, Object> body = new HashMap<>();
     * 
     * body.put("status", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
     * body.put("error", "InternalServerError");
     * body.put("message", "Erro no servidor de dados");
     * body.put("path", request.getServletPath());
     * 
     * final ObjectMapper mapper = new ObjectMapper();
     * mapper.writeValue(response.getOutputStream(), body);
     * }
     */

}
