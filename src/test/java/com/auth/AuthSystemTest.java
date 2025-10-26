package com.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic unit tests for AuthSystem covering happy path and key edge cases.
 */
public class AuthSystemTest {

    private AuthSystem auth;

    @BeforeEach
    void setUp() {
        auth = new AuthSystem();
    }

    @Test
    void testRegisterAndLoginSuccess() {
        String username = "alice";
        String password = "StrongP@ssw0rd123"; // meets complexity requirements

        assertTrue(auth.register(username, password), "Registration should succeed");

        String token = auth.login(username, password);
        assertNotNull(token, "Login should return a session token for valid credentials");
        assertTrue(auth.isSessionValid(token), "Session should be valid after login");
    }

    @Test
    void testLoginFailsForWrongPassword() {
        String username = "bob";
        String password = "StrongP@ssw0rd123";

        assertTrue(auth.register(username, password), "Registration should succeed");

        String token = auth.login(username, "incorrectPassword!");
        assertNull(token, "Login should fail with incorrect password");
    }

    @Test
    void testAccountLockoutAfterFailedAttempts() {
        String username = "carol";
        String password = "StrongP@ssw0rd123";

        assertTrue(auth.register(username, password), "Registration should succeed");

        // Trigger failed attempts up to the lockout threshold (5 attempts)
        for (int i = 0; i < 5; i++) {
            assertNull(auth.login(username, "wrong" + i), "Attempt " + i + " should fail");
        }

        // Now the account should be locked; even the correct password should not authenticate
        assertNull(auth.login(username, password), "Login should fail while account is locked");
    }

    @Test
    void testLogoutInvalidatesSession() {
        String username = "dave";
        String password = "StrongP@ssw0rd123";

        assertTrue(auth.register(username, password), "Registration should succeed");

        String token = auth.login(username, password);
        assertNotNull(token, "Login should return a session token for valid credentials");
        assertTrue(auth.isSessionValid(token), "Session should be valid after login");

        auth.logout(token);
        assertFalse(auth.isSessionValid(token), "Session should be invalid after logout");
    }
}
