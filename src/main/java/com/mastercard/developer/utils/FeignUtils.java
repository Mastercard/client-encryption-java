package com.mastercard.developer.utils;

import feign.RequestTemplate;
import feign.Response;

import java.util.*;

/**
 * Utility class for working with Feign objects.
 */
public class FeignUtils {

    private FeignUtils() {
    }

    /**
     * Update the value of an HTTP request header. Delete the header if the value is null.
     */
    public static void updateHeader(RequestTemplate request, String name, String value) {
        if (name == null) {
            // Do nothing
            return;
        }
        Map<String, Collection<String>> headers = request.headers();
        Set<String> headerNames = new HashSet<>(headers.keySet());
        for (String headerName : headerNames) {
            if (headerName.equalsIgnoreCase(name)) {
                request.header(name, (String)null);
            }
        }
        if (value != null) {
            request.header(name, value);
        }
    }

    /**
     * Update the value of an HTTP response header and return the updated response. Delete the header if the value is null.
     */
    public static Response updateHeader(Response response, String name, String value) {
        if (name == null) {
            // Do nothing
            return response;
        }
        Map<String, Collection<String>> headers = new HashMap<>(response.headers()); // Headers is an UnmodifiableMap
        Set<String> headerNames = new HashSet<>(headers.keySet());
        for (String headerName : headerNames) {
            if (headerName.equalsIgnoreCase(name)) {
                headers.remove(headerName);
            }
        }
        if (value != null) {
            headers.put(name, Collections.singleton(value));
        }
        return response.toBuilder()
                .headers(headers)
                .build();
    }

    /**
     * Return the value of an HTTP request header.
     */
    public static String readHeader(Response response, String name) {
        if (name == null) {
            // Do nothing
            return null;
        }
        Map<String, Collection<String>> headers = response.headers();
        Set<String> headerNames = headers.keySet();
        for (String headerName : headerNames) {
            if (headerName.equalsIgnoreCase(name)) {
                return (String) headers.get(headerName).toArray()[0];
            }
        }
        return null;
    }

    /**
     * Delete an HTTP response header.
     */
    public static Response removeHeader(Response response, String name) {
        return updateHeader(response, name, null);
    }
}
