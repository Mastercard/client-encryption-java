package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JsonSmartJsonEngine;
import org.junit.BeforeClass;

/**
 * Field Level Encryption tests using JSON Smart.
 */
public class FieldLevelEncryptionWithJsonSmartJsonEngineTest extends FieldLevelEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JsonSmartJsonEngine());
    }
}
