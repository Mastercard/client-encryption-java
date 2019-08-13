package com.mastercard.developer.json;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;

@Ignore
public abstract class BaseJsonEngineTest {

    protected static JsonEngine instanceUnderTest;

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
        String parentJsonPath1 = instanceUnderTest.getParentJsonPath(jsonPath1);
        String parentJsonPath2 = instanceUnderTest.getParentJsonPath(jsonPath2);
        String parentJsonPath3 = instanceUnderTest.getParentJsonPath(jsonPath3);
        String parentJsonPath4 = instanceUnderTest.getParentJsonPath(jsonPath4);

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
        String jsonElementKey1 = instanceUnderTest.getJsonElementKey(jsonPath1);
        String jsonElementKey2 = instanceUnderTest.getJsonElementKey(jsonPath2);
        String jsonElementKey3 = instanceUnderTest.getJsonElementKey(jsonPath3);
        String jsonElementKey4 = instanceUnderTest.getJsonElementKey(jsonPath4);

        // THEN
        Assert.assertEquals("obj2", jsonElementKey1);
        Assert.assertEquals("obj2", jsonElementKey2);
        Assert.assertEquals("obj2", jsonElementKey3);
        Assert.assertEquals("obj2", jsonElementKey4);
    }

    @Test
    public void testGetParentJsonPath_ShouldThrowIllegalArgumentException_WhenJsonPathNullOrEmpty() {

        // GIVEN
        String jsonPath = "";

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("json can not be null or empty");

        // WHEN
        instanceUnderTest.getParentJsonPath(jsonPath);
    }

    @Test
    public void testGetJsonElementKey_ShouldThrowIllegalArgumentException_WhenJsonPathNullOrEmpty() {

        // GIVEN
        String jsonPath = "";

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("json can not be null or empty");

        // WHEN
        instanceUnderTest.getJsonElementKey(jsonPath);
    }

    @Test
    public void testGetParentJsonPath_ShouldThrowIllegalStateException_WhenNoParent() {

        // GIVEN
        String jsonPath = "$";

        // THEN
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unable to find parent for '$'");

        // WHEN
        instanceUnderTest.getParentJsonPath(jsonPath);
    }

    @Test
    public void testGetJsonElementKey_ShouldThrowIllegalStateException_WhenNoKey() {

        // GIVEN
        String jsonPath = "$";

        // THEN
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Unable to find object key for '$'");

        // WHEN
        instanceUnderTest.getJsonElementKey(jsonPath);
    }

    @Test
    public void testToJsonString_ShouldThrowIllegalStateException_WhenNullObject() {
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Can't get a JSON string from a null object!");
        instanceUnderTest.toJsonString(null);
    }

    @Test
    public void testIsNullOrEmptyJson_Nominal() {
        Assert.assertTrue(instanceUnderTest.isNullOrEmptyJson(null));
        Assert.assertTrue(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("{}")));
        Assert.assertFalse(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("string")));
        Assert.assertFalse(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("true")));
        Assert.assertFalse(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("false")));
        Assert.assertFalse(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("123")));
        Assert.assertFalse(instanceUnderTest.isNullOrEmptyJson(instanceUnderTest.parse("{\"data\":123}")));
    }

    @Test
    public void testGetPropertyKeys_ShouldReturnEmptyList_WhenNullObject() {
        Assert.assertEquals(Collections.emptyList(), instanceUnderTest.getPropertyKeys(null));
    }
}
