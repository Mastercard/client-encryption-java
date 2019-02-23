package com.mastercard.developer.encryption;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;

import static org.hamcrest.core.Is.isA;

public class EncryptionExceptionTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testConstructor() throws Exception {

        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Something happened!");
        expectedException.expectCause(isA(IOException.class));

        throw new EncryptionException("Something happened!", new IOException());
    }
}
