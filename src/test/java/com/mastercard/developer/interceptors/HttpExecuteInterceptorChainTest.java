package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpRequest;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class HttpExecuteInterceptorChainTest {

    @Test
    public void testIntercept() throws IOException {

        // GIVEN
        HttpExecuteInterceptor interceptor1 = mock(HttpExecuteInterceptor.class);
        HttpExecuteInterceptor interceptor2 = mock(HttpExecuteInterceptor.class);
        List<HttpExecuteInterceptor> interceptors = Arrays.asList(interceptor1, interceptor2);
        HttpRequest request = mock(HttpRequest.class);

        // WHEN
        HttpExecuteInterceptorChain instanceUnderTest = new HttpExecuteInterceptorChain(interceptors);
        instanceUnderTest.intercept(request);

        // THEN
        verify(interceptor1).intercept(request);
        verify(interceptor2).intercept(request);
    }
}
