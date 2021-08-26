package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JsonSmartJsonEngine;
import org.junit.BeforeClass;

/**
 * JWE tests using JSON Smart.
 */
public class JweEncryptionWithJsonSmartJsonEngineTest extends JweEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JsonSmartJsonEngine());
    }
}
