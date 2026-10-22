package com.example.auth;

import com.example.auth.service.NotificationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    private static final String PASSWORD = "Str0ng@Pass";
    private static final AtomicInteger COUNTER = new AtomicInteger(1000);

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper om;
    @MockBean private NotificationService notificationService;

    private record TestUser(String email, String mobile) {}

    private TestUser newUser() {
        int n = COUNTER.incrementAndGet();
        return new TestUser("user" + n + "@example.com", "98765" + String.format("%05d", n));
    }

    private ResultActions register(TestUser u, String password, String confirm) throws Exception {
        return mvc.perform(post("/register").contentType(MediaType.APPLICATION_JSON)
                .content(om.writeValueAsString(Map.of(
                        "fullName", "Test User", "email", u.email(), "mobileNumber", u.mobile(),
                        "password", password, "confirmPassword", confirm))));
    }

    private ResultActions login(String identifier, String password) throws Exception {
        return mvc.perform(post("/login").contentType(MediaType.APPLICATION_JSON)
                .content(om.writeValueAsString(Map.of("identifier", identifier, "password", password))));
    }

    private String loginToken(String identifier, String password) throws Exception {
        String body = login(identifier, password).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return om.readTree(body).get("accessToken").asText();
    }

    private ResultActions authGet(String path, String token) throws Exception {
        return mvc.perform(get(path).header("Authorization", "Bearer " + token));
    }

    @Test
    void registerLoginAccessProtectedAndLogout() throws Exception {
        TestUser u = newUser();
        register(u, PASSWORD, PASSWORD).andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(u.email()))
                .andExpect(jsonPath("$.password").doesNotExist());

        String token = loginToken(u.email(), PASSWORD);
        authGet("/me", token).andExpect(status().isOk()).andExpect(jsonPath("$.email").value(u.email()));

        // login via mobile number also works
        loginToken(u.mobile(), PASSWORD);

        mvc.perform(post("/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.redirectUrl").value("/login"));

        authGet("/me", token).andExpect(status().isUnauthorized());
    }

    @Test
    void protectedApiRequiresAuthentication() throws Exception {
        mvc.perform(get("/me")).andExpect(status().isUnauthorized());
        authGet("/me", "not-a-real-token").andExpect(status().isUnauthorized());
    }

    @Test
    void duplicateEmailAndMobileAreRejected() throws Exception {
        TestUser u = newUser();
        register(u, PASSWORD, PASSWORD).andExpect(status().isCreated());
        register(u, PASSWORD, PASSWORD).andExpect(status().isConflict());

        TestUser sameMobile = new TestUser("other" + u.email(), u.mobile());
        register(sameMobile, PASSWORD, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void validationErrorsAreReportedPerField() throws Exception {
        mvc.perform(post("/register").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of(
                                "fullName", "ab", "email", "not-an-email", "mobileNumber", "123",
                                "password", "weak", "confirmPassword", "weak"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.fullName").exists())
                .andExpect(jsonPath("$.fieldErrors.email").exists())
                .andExpect(jsonPath("$.fieldErrors.mobileNumber").exists())
                .andExpect(jsonPath("$.fieldErrors.password").exists());

        register(newUser(), PASSWORD, "Different@123").andExpect(status().isBadRequest());
    }

    @Test
    void invalidLoginDoesNotRevealWhichPartWasWrong() throws Exception {
        TestUser u = newUser();
        register(u, PASSWORD, PASSWORD).andExpect(status().isCreated());

        login(u.email(), "Wrong@Pass1").andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
        login("nobody@example.com", PASSWORD).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    void changePasswordFlow() throws Exception {
        TestUser u = newUser();
        register(u, PASSWORD, PASSWORD).andExpect(status().isCreated());
        String token = loginToken(u.email(), PASSWORD);
        String otherDeviceToken = loginToken(u.email(), PASSWORD);

        String newPassword = "N3w@Password";
        // wrong current password
        mvc.perform(put("/change-password").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("currentPassword", "Wrong@Pass1",
                                "newPassword", newPassword, "confirmPassword", newPassword))))
                .andExpect(status().isBadRequest());

        mvc.perform(put("/change-password").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("currentPassword", PASSWORD,
                                "newPassword", newPassword, "confirmPassword", newPassword))))
                .andExpect(status().isOk());

        authGet("/me", token).andExpect(status().isOk());                       // current session kept
        authGet("/me", otherDeviceToken).andExpect(status().isUnauthorized());  // other sessions ended
        login(u.email(), PASSWORD).andExpect(status().isUnauthorized());
        loginToken(u.email(), newPassword);
    }

    @Test
    void forgotVerifyAndResetPasswordFlow() throws Exception {
        TestUser u = newUser();
        register(u, PASSWORD, PASSWORD).andExpect(status().isCreated());
        String oldToken = loginToken(u.email(), PASSWORD);

        mvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("identifier", u.email()))))
                .andExpect(status().isOk());

        ArgumentCaptor<String> otp = ArgumentCaptor.forClass(String.class);
        verify(notificationService).sendOtp(eq(u.email()), otp.capture());

        // wrong OTP is rejected
        String wrong = otp.getValue().equals("000000") ? "111111" : "000000";
        mvc.perform(post("/verify-otp").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("identifier", u.email(), "otp", wrong))))
                .andExpect(status().isBadRequest());

        String body = mvc.perform(post("/verify-otp").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("identifier", u.email(), "otp", otp.getValue()))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String resetToken = om.readTree(body).get("resetToken").asText();

        String newPassword = "R3set@Password";
        mvc.perform(post("/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("resetToken", resetToken,
                                "newPassword", newPassword, "confirmPassword", newPassword))))
                .andExpect(status().isOk());

        authGet("/me", oldToken).andExpect(status().isUnauthorized());          // sessions invalidated
        login(u.email(), PASSWORD).andExpect(status().isUnauthorized());
        loginToken(u.email(), newPassword);

        // reset token is single-use
        mvc.perform(post("/reset-password").contentType(MediaType.APPLICATION_JSON)
                        .content(om.writeValueAsString(Map.of("resetToken", resetToken,
                                "newPassword", "An0ther@Pass", "confirmPassword", "An0ther@Pass"))))
                .andExpect(status().isBadRequest());
    }
}
