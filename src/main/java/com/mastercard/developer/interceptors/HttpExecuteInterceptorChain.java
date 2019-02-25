package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpRequest;

import java.io.IOException;
import java.util.List;

/**
 * Helper to chain multiple Google Client API request interceptors.
 */
public class HttpExecuteInterceptorChain implements HttpExecuteInterceptor {

    private final List<HttpExecuteInterceptor> requestInterceptors;

    public HttpExecuteInterceptorChain(List<HttpExecuteInterceptor> requestInterceptors) {
        this.requestInterceptors = requestInterceptors;
    }

    @Override
    public void intercept(HttpRequest request) throws IOException {
        for (HttpExecuteInterceptor interceptor: requestInterceptors) {
            interceptor.intercept(request);
        }
    }
}
