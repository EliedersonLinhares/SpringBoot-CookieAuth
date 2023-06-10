package com.esl.springbootlogin.event;

import java.util.UUID;

import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import com.esl.springbootlogin.model.User;
import com.esl.springbootlogin.services.AuthService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    private final AuthService authService;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {

        // 1 - Get the newly registered user
        User theUser = event.getUser();
        // 2 - Create a verification token for the user
        String verificationToken = UUID.randomUUID().toString();
        // 3 - Save the verification token for the user
        authService.saveUserVerificationToken(theUser, verificationToken);
        // 4 - Buid the verificationUrl to be sento to the user
        String url = event.getApplicationUrl() + "/api/auth/verifyemail?token=" + verificationToken;
        // 5 - Send the email

        log.info("Url example: {}", url);
    }

}
