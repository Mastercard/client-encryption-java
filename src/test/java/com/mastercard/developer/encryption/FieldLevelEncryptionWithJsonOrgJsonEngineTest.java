package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JsonOrgJsonEngine;
import org.junit.BeforeClass;

/**
 * Field Level Encryption tests using JSON Org.
 */
public class FieldLevelEncryptionWithJsonOrgJsonEngineTest extends FieldLevelEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JsonOrgJsonEngine());
    }
}
