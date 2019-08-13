package com.mastercard.developer.json;

import org.junit.BeforeClass;

public class JacksonJsonEngineTest extends BaseJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        instanceUnderTest = new JacksonJsonEngine();
    }
}
