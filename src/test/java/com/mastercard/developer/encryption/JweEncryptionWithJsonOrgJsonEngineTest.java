package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JsonOrgJsonEngine;
import org.junit.BeforeClass;

/**
 * JWE Encryption tests using JSON Org.
 */
public class JweEncryptionWithJsonOrgJsonEngineTest extends JweEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JsonOrgJsonEngine());
    }
}
