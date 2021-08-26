package com.mastercard.developer.encryption;

import com.mastercard.developer.json.GsonJsonEngine;
import org.junit.BeforeClass;

/**
 * JWE Encryption tests using Google Gson.
 */
public class JweEncryptionWithGsonJsonEngineTest extends JweEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new GsonJsonEngine());
    }
}
