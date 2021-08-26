package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JacksonJsonEngine;
import org.junit.BeforeClass;

/**
 * JWE Encryption tests using Jackson.
 */
public class JweEncryptionWithJacksonJsonEngineTest extends JweEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JacksonJsonEngine());
    }
}
