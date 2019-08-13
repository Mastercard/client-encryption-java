package com.mastercard.developer.json;

import org.junit.BeforeClass;

public class JettisonJsonEngineTest extends BaseJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        instanceUnderTest = new JettisonJsonEngine();
    }
}
