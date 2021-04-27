package com.mastercard.developer.encryption;

import com.mastercard.developer.json.JettisonJsonEngine;
import org.junit.BeforeClass;

/**
 * Field Level Encryption tests using Jettison.
 */
public class FieldLevelEncryptionWithJettisonJsonEngineTest extends FieldLevelEncryptionWithDefaultJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        JsonParser.withJsonEngine(new JettisonJsonEngine());
    }
}
