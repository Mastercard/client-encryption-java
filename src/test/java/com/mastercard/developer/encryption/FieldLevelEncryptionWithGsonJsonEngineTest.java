package com.mastercard.developer.encryption;

import com.mastercard.developer.json.GsonJsonEngine;
import org.junit.BeforeClass;

/**
 * Field Level Encryption tests using Google Gson.
 */
public class FieldLevelEncryptionWithGsonJsonEngineTest extends FieldLevelEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new GsonJsonEngine());
    }
}
