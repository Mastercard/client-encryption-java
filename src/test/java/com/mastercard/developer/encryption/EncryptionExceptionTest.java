package com.mastercard.developer.encryption;
import org.junit.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EncryptionExceptionTest {

    @Test
    public void testConstructor() {
        try {
            throw new EncryptionException("Something happened!", new IOException());
        } catch (EncryptionException e) {
            // Assert that the exception message is correct
            assertEquals("Something happened!", e.getMessage());

            // Assert that the cause of the exception is of type IOException
            assertTrue(e.getCause() instanceof IOException);
        }
    }
}
