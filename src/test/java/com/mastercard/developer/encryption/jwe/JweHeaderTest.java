package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.json.JsonEngine;
import org.junit.Test;

import static org.junit.Assert.*;

public class JweHeaderTest {

    @Test
    public void testToJson_ShouldReturnJsonJweHeader() {
        JweHeader header = new JweHeader("RSA-OAEP-256", "A256GCM", "123", "application/json");
        assertEquals("{\"kid\":\"123\",\"cty\":\"application/json\",\"enc\":\"A256GCM\",\"alg\":\"RSA-OAEP-256\"}", header.toJson());
    }

    @Test
    public void testParseJweHeader_ShouldCorrectlyParseJweHeader() {
        JweHeader header = JweHeader.parseJweHeader("eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb25cL2pzb24iLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0", JsonEngine.getDefault());
        assertEquals("A256GCM", header.getEnc());
        assertEquals("RSA-OAEP-256", header.getAlg());
        assertEquals("application/json", header.getCty());
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", header.getKid());
    }
}
