package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JettisonJsonEngine;
import org.junit.BeforeClass;

/**
 * JWE Encryption tests using Jettison.
 */
public class JweEncryptionWithJettisonJsonEngineTest extends JweEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JettisonJsonEngine());
    }
}
