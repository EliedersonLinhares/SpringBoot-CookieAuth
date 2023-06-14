package com.esl.springbootlogin.event;

import java.io.UnsupportedEncodingException;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.mail.javamail.MimeMessageHelper;

import com.esl.springbootlogin.model.User;
import com.esl.springbootlogin.services.AuthService;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    private final AuthService authService;
    private final JavaMailSender mailSender;
    private User theUser;

    @Value("${spring.mail.username}")
    private String senderMail;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {

        // 1 - Get the newly registered user
        theUser = event.getUser();
        // 2 - Create a verification token for the user
        String verificationToken = UUID.randomUUID().toString();
        // 3 - Save the verification token for the user
        authService.saveUserVerificationToken(theUser, verificationToken);
        // 4 - Buid the verificationUrl to be sento to the user
        String url = event.getApplicationUrl() + "/api/auth/verifyemail?token=" + verificationToken;
        // 5 - Send the email
        try {
            sendVerificationEmail(url);
        } catch (MessagingException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        log.info("Url example: {}", url);
    }

    public void sendVerificationEmail(String url) throws MessagingException, UnsupportedEncodingException {
        String subject = "Confimação de cadastro";
        String senderName = "Teste de cadastro com springboot";
        String mailContent = "<p> Olá, " + theUser.getUsername() + ", </p>" +
                "<p>Obrigado por se cadastrar em nosso site," + "" +
                "Por favor, clique no link abaixo, ou copie e cole no seu navegador.</p>" +
                "<a href=\"" + url + "\">Confirme seu email para ativar sua conta</a>" +
                "<p> Obrigado <br>Portal de cadastro de usuários";
        MimeMessage message = mailSender.createMimeMessage();
        var messageHelper = new MimeMessageHelper(message);
        messageHelper.setFrom(senderMail, senderName);
        messageHelper.setTo(theUser.getEmail());
        messageHelper.setSubject(subject);
        messageHelper.setText(mailContent, true);
        mailSender.send(message);
    }

}
