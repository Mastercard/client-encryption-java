package com.mastercard.developer.json;

import org.junit.BeforeClass;

public class GsonJsonEngineTest extends BaseJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        instanceUnderTest = new GsonJsonEngine();
    }
}
