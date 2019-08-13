package com.mastercard.developer.json;

import org.junit.BeforeClass;

public class JsonOrgJsonEngineTest extends BaseJsonEngineTest {

    @BeforeClass
    public static void setUpJsonProvider() {
        instanceUnderTest = new JsonOrgJsonEngine();
    }
}
