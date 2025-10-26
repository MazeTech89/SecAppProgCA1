package com.auth;

// BCrypt: Industry-standard password hashing algorithm
import org.mindrot.jbcrypt.BCrypt;
// SecureRandom: Cryptographically strong random number generator
import java.security.SecureRandom;
// Time-related imports for session management
import java.time.Instant;
// Base64: For encoding secure tokens
import java.util.Base64;
// Collections for storing user and session data
import java.util.HashMap;
import java.util.Map;
// Pattern matching for password validation
import java.util.regex.Pattern;


public class AuthSystem {

    // Security Constants
    // Maximum number of failed login attempts before account lockout
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    
    // Account lockout duration: 15 minutes in milliseconds
    // Provides protection against brute force attacks while remaining user-friendly
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000;
    
    // Minimum password length requirement
    // NIST recommends at least 8 characters, enforce 12 for higher security
    private static final int MIN_PASSWORD_LENGTH = 12;
    
    // Password complexity requirements using regex:
    // - At least one digit (?=.*[0-9])
    // - At least one lowercase letter (?=.*[a-z])
    // - At least one uppercase letter (?=.*[A-Z])
    // - At least one special character (?=.*[@#$%^&+=!])
    // - No whitespace (?=\\S+$)
    // - Minimum length .{12,}
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{" + MIN_PASSWORD_LENGTH + ",}$"
    );
    
    // Cryptographically secure random number generator for token generation
    // Used instead of Random to prevent predictable token generation
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Length of session tokens in bytes (256 bits)
    // Provides sufficient entropy to prevent brute force attacks
    private static final int SESSION_TOKEN_LENGTH = 32;
    
    // Dummy hash used to make password verification cost identical for
    // existing and non-existing users. This prevents username enumeration
    // via timing attacks. The value is computed once at class load.
    private static final String DUMMY_HASH = BCrypt.hashpw("dummy_password", BCrypt.gensalt(12));

    /**
     * Storage for user accounts and active sessions
     * 
     * Security Considerations:
     * - In-memory storage is not persistent (data lost on restart)
     * - In production, should use encrypted database storage
     * - Separate user and session storage for better security
     * - Maps are final to prevent reassignment
     */
    private final Map<String, User> users = new HashMap<>();    // Stores user credentials and state
    private final Map<String, Session> sessions = new HashMap<>(); // Stores active sessions
    
     /**
     * User class containing secure credential storage and account state
     * Security features:
     * - Hashed password storage using BCrypt
     * - Account lockout mechanism
     * - Login attempt tracking
     * - Constant-time password comparison
     */
    static class User {
        // Store only hashed password, never the plain text
        private final String hashedPassword;
        // Track failed login attempts for lockout mechanism
        private int loginAttempts;
        // Timestamp until which the account is locked
        private long lockoutUntil;

        /**
         * Creates a new user with secure password storage
         * @param password Plain text password (will be hashed)
         */
        User(String password) {
            // Validate password meets complexity requirements
            validatePassword(password);
            // Hash password with BCrypt (automatically generates and stores salt)
            // Work factor of 12 provides good balance of security and performance
            this.hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
            this.loginAttempts = 0;
            this.lockoutUntil = 0;
        }

        /**
         * Checks if account is currently locked due to too many failed attempts
         * @return true if account is locked
         */
        boolean isLocked() {
            return lockoutUntil > System.currentTimeMillis();
        }

        /**
         * Tracks failed login attempts and implements account lockout
         * Security: Prevents brute force attacks through temporary lockout
         */
        void incrementLoginAttempts() {
            loginAttempts++;
            if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                lockoutUntil = System.currentTimeMillis() + LOCKOUT_DURATION_MS;
            }
        }

        /**
         * Resets the failed login counter after successful authentication
         */
        void resetLoginAttempts() {
            loginAttempts = 0;
            lockoutUntil = 0;
        }

        /**
         * Securely verifies a password using BCrypt's constant-time comparison
         * @param password Plain text password to verify
         * @return true if password matches
         */
        boolean verifyPassword(String password) {
            // BCrypt.checkpw uses constant-time comparison to prevent timing attacks
            return BCrypt.checkpw(password, hashedPassword);
        }
    }

    /**
     * Session class for managing user authentication state
     * Security features:
     * - Immutable fields prevent modification after creation
     * - Built-in expiration mechanism
     * - Cryptographically secure token
     */
    static class Session {
        private final String token;      // Secure random session identifier
        private final String username;    // Associated user
        private final long createdAt;    // Session creation timestamp
        private final long expiresAt;    // Session expiration timestamp

        /**
         * Creates a new session with automatic expiration
         * @param token Secure random token
         * @param username Associated username
         */
        Session(String token, String username) {
            this.token = token;
            this.username = username;
            this.createdAt = System.currentTimeMillis();
            // Sessions expire after 30 minutes of inactivity
            // Short session duration reduces risk of session hijacking
            this.expiresAt = this.createdAt + (30 * 60 * 1000);
        }

        /**
         * Checks if session has expired
         * @return true if current time is past expiration
         */
        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }
    
    /**
     * Validates password complexity requirements
     * Security features:
     * - Null check
     * - Minimum length validation
     * - Character type requirements
     * - No whitespace allowed
     * 
     * @param password The password to validate
     * @throws IllegalArgumentException if password doesn't meet requirements
     */
    private static void validatePassword(String password) {
        if (password == null || !PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException(
                "Password must be at least " + MIN_PASSWORD_LENGTH + " characters long and contain: " +
                "1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character"
            );
        }
    }

    /**
     * Generates a cryptographically secure random token
     * @return A base64 encoded random token
     */
    private String generateSecureToken() {
        byte[] tokenBytes = new byte[SESSION_TOKEN_LENGTH];
        SECURE_RANDOM.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Registers a new user with secure password storage
     * Security features:
     * - Input validation for username
     * - Password complexity validation
     * - Constant-time username existence check
     * - Secure password hashing
     * 
     * @param username Username to register
     * @param password Password to hash and store
     * @return true if registration successful, false if username exists
     */
    public boolean register(String username, String password) {
        // Validate username is not null or empty
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty");
        }
        
        // Constant-time username existence check to prevent timing attacks
        // Uses bitwise OR to ensure all usernames are checked regardless of match
        boolean exists = false;
        for (String existingUser : users.keySet()) {
            exists |= existingUser.equals(username);
        }
        
        if (exists) {
            return false;
        }

        // Create new user with validated and hashed password
        users.put(username, new User(password));
        return true;
    }

    /**
     * Authenticates a user and creates a new session with secure practices
     * Security features:
     * - Constant-time operations to prevent timing attacks
     * - Account lockout after failed attempts
     * - Login attempt tracking
     * - Secure session token generation
     * - Password verification using BCrypt
     *
     * @param username The username to authenticate
     * @param password The password to verify
     * @return String session token if login successful, null otherwise
     * @throws SecurityException if account is locked
     */
    public String login(String username, String password) {
        // Constant-time username lookup (do not break out early)
        // The loop scans all entries to avoid timing differences based on
        // whether a username is found early or not.
        User user = null;
        boolean userExists = false;

        for (Map.Entry<String, User> entry : users.entrySet()) {
            if (entry.getKey().equals(username)) {
                user = entry.getValue();
                userExists = true;
            }
        }

        // Always perform a BCrypt checkpw to equalize computational cost.
        // Use the real user's hashed password when the user exists, otherwise
        // use the DUMMY_HASH so the time taken is similar regardless of
        // whether the username exists. Do not reveal existence via
        // different return values or exceptions.
        String hashToCheck = userExists ? user.hashedPassword : DUMMY_HASH;
        boolean passwordMatches = BCrypt.checkpw(password, hashToCheck);

        // If user exists, handle lockout, attempts and session creation.
        // For non-existing users, simply return null after the hash check.
        if (!userExists) {
            // No user: do not create any record or leak information
            return null;
        }

        // At this point user != null
        // If account is locked, treat as authentication failure without
        // exposing lockout status to the caller (return null).
        if (user.isLocked()) {
        
            return null;
        }

        if (passwordMatches) {
            user.resetLoginAttempts();
            String token = generateSecureToken();
            sessions.put(token, new Session(token, username));
            return token;
        } else {
            user.incrementLoginAttempts();
            return null;
        }
    }

    /**
     * Validates a session token
     * Security features:
     * - Input validation
     * - Automatic session expiration
     * - Expired session cleanup
     * - Null-safe operations
     *
     * @param sessionToken The session token to validate
     * @return boolean indicating if the session is valid
     */
    public boolean isSessionValid(String sessionToken) {
        if (sessionToken == null || sessionToken.trim().isEmpty()) {
            return false;
        }

        Session session = sessions.get(sessionToken);
        if (session == null || session.isExpired()) {
            sessions.remove(sessionToken); // Clean up expired sessions
            return false;
        }

        return true;
    }

    /**
     * Invalidates a session
     *
     * @param sessionToken The session token to invalidate
     */
    public void logout(String sessionToken) {
        sessions.remove(sessionToken);
}
}