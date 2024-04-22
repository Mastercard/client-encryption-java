package com.mastercard.developer.utils;

import feign.Request;
import feign.Response;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;

public class HttpHelpers {

    public static Response buildResponse(String payload) {
        Response response = Response.builder()
                .status(200)
                .headers(new HashMap<String, Collection<String>>())
                .body(payload, StandardCharsets.UTF_8)
                .request(buildDummyRequest(payload))
                .build();
        return response;
    }

    public static Response buildResponse(String payload,   HashMap<String, Collection<String>> headers) {
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(payload, StandardCharsets.UTF_8)
                .request(buildDummyRequest(payload))
                .build();
        return response;
    }
    public static Request buildDummyRequest(String payload) {
        return Request.create(Request.HttpMethod.GET, "http://example.com", new HashMap<>(), payload.getBytes(),StandardCharsets.UTF_8);
    }
}

