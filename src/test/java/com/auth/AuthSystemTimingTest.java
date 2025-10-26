package com.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Timing-related test to help detect username enumeration via timing differences.
 *
 * This test runs multiple iterations and asserts the average times are
 * within a reasonable threshold.
 */
public class AuthSystemTimingTest {

    private AuthSystem auth;

    @BeforeEach
    void setUp() {
        auth = new AuthSystem();
    }

    @Test
    void testLoginTimingIndistinguishableBetweenExistingAndNonExistingUsers() {
        String existingUser = "timingUser";
        String password = "StrongP@ssw0rd1";
        assertTrue(auth.register(existingUser, password), "Registration should succeed");

        // 
        // an existing user and a non-existing user. The AuthSystem should perform
        // a BCrypt check for both and therefore timing should be similar.

        final int warmup = 5;
        final int iterations = 40;
        // Threshold in milliseconds for average difference
        final double thresholdMs = 50.0;

        // Warmup to stabilize JIT and bcrypt cost
        for (int i = 0; i < warmup; i++) {
            auth.login(existingUser, "wrongPass");
            auth.login("noSuchUser" + i, "wrongPass");
        }

        long totalExistingNs = 0;
        long totalNonExistingNs = 0;

        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            auth.login(existingUser, "wrongPass");
            long t1 = System.nanoTime();
            totalExistingNs += (t1 - t0);

            long t2 = System.nanoTime();
            auth.login("noSuchUser_test" + i, "wrongPass");
            long t3 = System.nanoTime();
            totalNonExistingNs += (t3 - t2);
        }

        double avgExistingMs = (totalExistingNs / (double) iterations) / 1_000_000.0;
        double avgNonExistingMs = (totalNonExistingNs / (double) iterations) / 1_000_000.0;

        // Debug output (useful when running locally)
        System.out.printf("avgExisting=%.2fms avgNonExisting=%.2fms\n", avgExistingMs, avgNonExistingMs);

        double diff = Math.abs(avgExistingMs - avgNonExistingMs);
        assertTrue(diff <= thresholdMs, "Timing difference (ms) should be <= " + thresholdMs + " but was " + diff);
    }
}
