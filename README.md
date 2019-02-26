# client-encryption-java

[![](https://travis-ci.org/Mastercard/client-encryption-java.svg?branch=master)](https://travis-ci.org/Mastercard/client-encryption-java)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-java&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-java) 
[![](https://img.shields.io/maven-central/v/com.mastercard.developer/client-encryption.svg)](https://search.maven.org/artifact/com.mastercard.developer/client-encryption/)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-java/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Loading the Encryption Certificate](#loading-the-encryption-certificate) 
  * [Loading the Decryption Key](#loading-the-decryption-key)
  * [Performing Field Level Encryption and Decryption](#performing-field-level-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Zero dependency library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
Java 7+

### References <a name="references"></a>
* [Encryption of sensitive data](https://developer.mastercard.com/page/mdes-token-connect-encryption-of-sensitive-data) guide

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive:
* A public request encryption certificate (aka _Client Encryption Keys_)
* A private response decryption key (aka _Mastercard Encryption Keys_)

### Adding the Library to Your Project <a name="adding-the-library-to-your-project"></a>

#### Maven
```xml
<dependency>
    <groupId>com.mastercard.developer</groupId>
    <artifactId>client-encryption</artifactId>
    <version>${client-encryption-version}</version>
</dependency>
```

#### Gradle
```
dependencies {
    implementation "com.mastercard.developer:client-encryption:$clientEncryptionVersion"
}	
```

#### Other Dependency Managers
See: https://search.maven.org/artifact/com.mastercard.developer/client-encryption

### Loading the Encryption Certificate <a name="loading-the-encryption-certificate"></a>

A `Certificate` object can be created from a PEM file by calling the `EncryptionUtils.loadEncryptionCertificate` method:
```java
Certificate encryptionCertificate = EncryptionUtils.loadEncryptionCertificate("<insert PEM certificate file path>");
```

### Loading the Decryption Key <a name="loading-the-decryption-key"></a>

#### From a PKCS#12 File

A `PrivateKey` key object can be created from a PKCS#12 file by calling the `EncryptionUtils.loadDecryptionKey` method:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey(
                        "<insert PKCS#12 key file path>", 
                        "<insert key alias>", 
                        "<insert key password>");
```

#### From a PKCS#8 Formatted Key

A `PrivateKey` object can be created from a PKCS#8 key file by calling the `EncryptionUtils.loadDecryptionKey` method:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey("<insert PKCS#8 file path>");
```

#### From a PEM Formatted Key

Reading PEM encoded keys requires an additional step:

1. Convert the key using: `openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem -out key.der -nocrypt`
2. Call `EncryptionUtils.loadDecryptionKey` (see above)

### Performing Field Level Encryption and Decryption <a name="performing-field-level-encryption-and-decryption"></a>
The methods that do all the heavy lifting are `encryptPayload` and `decryptPayload` in the `FieldLevelEncryption` class.

* `encryptPayload` usage:
```java
String encryptedRequestPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);
```

* `decryptPayload` usage:
```java
String responsePayload = FieldLevelEncryption.decryptPayload(encryptedResponsePayload, config);
```

#### Configuring the Field Level Encryption <a name="configuring-the-field-level-encryption"></a>
Use the `FieldLevelEncryptionConfigBuilder` to create `FieldLevelEncryptionConfig` instances. Example:
```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
                .withEncryptionCertificate(encryptionCertificate)
                .withDecryptionKey(decryptionKey)
                .withEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
                .withDecryptionPath("$.path.to.encryptedFoo", "$.path.to.foo")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withEncryptedValueFieldName("encryptedValue")
                .withEncryptedKeyFieldName("encryptedKey")
                .withIvFieldName("iv")
                .withFieldValueEncoding(FieldValueEncoding.HEX)
                .build();
```

See also [FieldLevelEncryptionConfigBuilder.java](https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/encryption/FieldLevelEncryptionConfigBuilder.java) for all config options.

#### Performing Encryption

Call `FieldLevelEncryption.encryptPayload` with a JSON request payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```java
String payload = "{" +
        "    \"path\": {" +
        "        \"to\": {" +
        "            \"foo\": {" +
        "                \"sensitiveField1\": \"sensitiveValue1\"," +
        "                \"sensitiveField2\": \"sensitiveValue2\"" +
        "            }" +
        "        }" +
        "    }" +
        "}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "iv": "7f1105fb0c684864a189fb3709ce3d28",
                "encryptedKey": "67f467d1b653d98411a0c6d3c(...)ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedValue": "b73aabd267517fc09ed72455c2(...)dffb5fa04bf6e6ce9ade1ff514ed6141"
            }
        }
    }
}
```

#### Performing Decryption

Call `FieldLevelEncryption.decryptPayload` with a JSON response payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```java
String encryptedPayload = "{" +
        "    \"path\": {" +
        "        \"to\": {" +
        "            \"encryptedFoo\": {" +
        "                \"iv\": \"e5d313c056c411170bf07ac82ede78c9\"," +
        "                \"encryptedKey\": \"e3a56746c0f9109d18b3a2652b76(...)f16d8afeff36b2479652f5c24ae7bd\"," +
        "                \"encryptedValue\": \"809a09d78257af5379df0c454dcdf(...)353ed59fe72fd4a7735c69da4080e74f\"" +
        "            }" +
        "        }" +
        "    }" +
        "}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
    "path": {
        "to": {
            "foo": {
                "sensitiveField1": "sensitiveValue1",
                "sensitiveField2": "sensitiveValue2"
            }
        }
    }
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The `com.mastercard.developer.interceptors` package will provide you with some interceptor classes you can use when configuring your API client. These classes will take care of encrypting/decrypting request and response payloads.

Library options currently supported for the `java` generator:
+ [okhttp-gson](#okhttp-gson)
+ [retrofit](#retrofit)
+ [retrofit2](#retrofit2)
+ [google-api-client](#google-api-client)

See also:
* [OpenAPI Generator (maven Plugin)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-maven-plugin) 
* [CONFIG OPTIONS for java](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/java.md)

#### okhttp-gson <a name="okhttp-gson"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>okhttp-gson</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttp2FieldLevelEncryptionInterceptor`
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
List<Interceptor> interceptors = client.getHttpClient().networkInterceptors();
interceptors.add(new OkHttp2FieldLevelEncryptionInterceptor(config));
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = new ServiceApi(client);
// ...
```

#### retrofit <a name="retrofit"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttp2FieldLevelEncryptionInterceptor`
```java
ApiClient client = new ApiClient();
RestAdapter.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.setEndpoint("https://sandbox.api.mastercard.com"); 
List<Interceptor> interceptors = client.getOkClient().networkInterceptors();
interceptors.add(new OkHttp2FieldLevelEncryptionInterceptor(config));
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

#### retrofit2 <a name="retrofit2"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit2</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttpFieldLevelEncryptionInterceptor`
```java
ApiClient client = new ApiClient();
Retrofit.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.baseUrl("https://sandbox.api.mastercard.com"); 
OkHttpClient.Builder okBuilder = client.getOkBuilder();
okBuilder.addNetworkInterceptor(new OkHttpFieldLevelEncryptionInterceptor(config));
okBuilder.addNetworkInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

#### google-api-client <a name="google-api-client"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>google-api-client</library>
    <!-- ... -->
</configuration>
```

##### Usage of `HttpExecuteFieldLevelEncryptionInterceptor` and `HttpExecuteInterceptorChain`
```java
HttpRequestInitializer initializer = new HttpRequestInitializer() {
    @Override
    public void initialize(HttpRequest request) {
        HttpExecuteOAuth1Interceptor authenticationInterceptor = new HttpExecuteOAuth1Interceptor(consumerKey, signingKey);
        HttpExecuteFieldLevelEncryptionInterceptor encryptionInterceptor = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        request.setInterceptor(new HttpExecuteInterceptorChain(Arrays.asList(encryptionInterceptor, authenticationInterceptor)));
        request.setResponseInterceptor(encryptionInterceptor);
    }
};
ApiClient client = new ApiClient("https://sandbox.api.mastercard.com", null, initializer, null);
ServiceApi serviceApi = client.serviceApi();
// ...
```