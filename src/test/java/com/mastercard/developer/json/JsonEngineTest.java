package com.mastercard.developer.json;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class JsonEngineTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testGetParentJsonPath_Nominal() {

        // GIVEN
        String jsonPath1 = "$['obj1']['obj2']['obj3']";
        String jsonPath2 = "obj1.obj2";
        String jsonPath3 = "$.obj1.obj2";
        String jsonPath4 = "obj1";

        // WHEN
        String parentJsonPath1 = JsonEngine.getParentJsonPath(jsonPath1);
        String parentJsonPath2 = JsonEngine.getParentJsonPath(jsonPath2);
        String parentJsonPath3 = JsonEngine.getParentJsonPath(jsonPath3);
        String parentJsonPath4 = JsonEngine.getParentJsonPath(jsonPath4);

        // THEN
        Assert.assertEquals("$['obj1']['obj2']", parentJsonPath1);
        Assert.assertEquals("$['obj1']", parentJsonPath2);
        Assert.assertEquals("$['obj1']", parentJsonPath3);
        Assert.assertEquals("$", parentJsonPath4);
    }

    @Test
    public void testGetJsonElementKey_Nominal() {

        // GIVEN
        String jsonPath1 = "$['obj0']['obj1']['obj2']";
        String jsonPath2 = "obj1.obj2";
        String jsonPath3 = "$.obj1.obj2";
        String jsonPath4 = "obj2";

        // WHEN
        String jsonElementKey1 = JsonEngine.getJsonElementKey(jsonPath1);
        String jsonElementKey2 = JsonEngine.getJsonElementKey(jsonPath2);
        String jsonElementKey3 = JsonEngine.getJsonElementKey(jsonPath3);
        String jsonElementKey4 = JsonEngine.getJsonElementKey(jsonPath4);

        // THEN
        Assert.assertEquals("obj2", jsonElementKey1);
        Assert.assertEquals("obj2", jsonElementKey2);
        Assert.assertEquals("obj2", jsonElementKey3);
        Assert.assertEquals("obj2", jsonElementKey3);
    }

    @Test
    public void testGetParentJsonPath_ShouldThrowIllegalArgumentException_WhenJsonPathNullOrEmpty() {

        // GIVEN
        String jsonPath = "";

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("json can not be null or empty");

        // WHEN
        JsonEngine.getParentJsonPath(jsonPath);
    }

    @Test
    public void testGetJsonElementKey_ShouldThrowIllegalArgumentException_WhenJsonPathNullOrEmpty() {

        // GIVEN
        String jsonPath = "";

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("json can not be null or empty");

        // WHEN
        JsonEngine.getJsonElementKey(jsonPath);
    }

    @Test
    public void testGetParentJsonPath_ShouldThrowIllegalStateException_WhenNoParent() {

        // GIVEN
        String jsonPath = "$";

        // THEN
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unable to find parent for '$'");

        // WHEN
        JsonEngine.getParentJsonPath(jsonPath);
    }

    @Test
    public void testGetJsonElementKey_ShouldThrowIllegalStateException_WhenNoKey() {

        // GIVEN
        String jsonPath = "$";

        // THEN
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unable to find object key for '$'");

        // WHEN
        JsonEngine.getJsonElementKey(jsonPath);
    }
}
