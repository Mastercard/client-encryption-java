package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JacksonJsonEngine;
import org.junit.BeforeClass;

/**
 * Field Level Encryption tests using Jackson.
 */
public class FieldLevelEncryptionWithJacksonJsonEngineTest extends FieldLevelEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JacksonJsonEngine());
    }
}
