package com.mastercard.developer.json;

import org.junit.BeforeClass;

public class JsonSmartJsonEngineTest  extends BaseJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        instanceUnderTest = new JsonSmartJsonEngine();
    }
}
