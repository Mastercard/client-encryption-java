# client-encryption-java
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)

[![](https://github.com/Mastercard/client-encryption-java/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-java/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-java&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-java)
[![](https://github.com/Mastercard/client-encryption-java/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-java/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/maven-central/v/com.mastercard.developer/client-encryption.svg)](https://search.maven.org/artifact/com.mastercard.developer/client-encryption/)
[![](https://www.javadoc.io/badge/com.mastercard.developer/client-encryption.svg?color=blue)](https://www.javadoc.io/doc/com.mastercard.developer/client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-java/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Selecting a JSON Engine](#selecting-a-json-engine)
  * [Loading the Encryption Certificate](#loading-the-encryption-certificate) 
  * [Loading the Decryption Key](#loading-the-decryption-key)
  * [Performing Payload Encryption and Decryption](#performing-payload-encryption-and-decryption)
    * [Introduction](#introduction)
    * [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
    * [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Library for Mastercard API compliant payload encryption/decryption.

### Compatibility <a name="compatibility"></a>
Java 8+

### References <a name="references"></a>
* [JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
* [Securing Sensitive Data Using Payload Encryption](https://developer.mastercard.com/platform/documentation/security-and-authentication/securing-sensitive-data-using-payload-encryption/)

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

### Selecting a JSON Engine <a name="selecting-a-json-engine"></a>

This library requires one of the following dependencies to be added to your classpath:

* [Jackson](https://search.maven.org/artifact/com.fasterxml.jackson.core/jackson-databind) 2.4.5+
* [Google Gson](https://search.maven.org/artifact/com.google.code.gson/gson) 2.3.1+
* [Json-smart](https://search.maven.org/artifact/net.minidev/json-smart) 2.1.1+
* [Jettison](https://search.maven.org/artifact/org.codehaus.jettison/jettison) 1.0+
* [Org JSON](https://search.maven.org/artifact/org.json/json) 20070829+

You can either let the library choose for you, or force the one to be used by calling `withJsonEngine` on the `JsonParser` class.
Example:

```java
JsonParser.withJsonEngine(new JettisonJsonEngine());
```

Available engine classes: 
* `GsonJsonEngine`
* `JacksonJsonEngine`
* `JettisonJsonEngine`
* `JsonOrgJsonEngine`
* `JsonSmartJsonEngine`

### Loading the Encryption Certificate <a name="loading-the-encryption-certificate"></a>

A `Certificate` object can be created from a file by calling `EncryptionUtils.loadEncryptionCertificate`:
```java
Certificate encryptionCertificate = EncryptionUtils.loadEncryptionCertificate("<insert certificate file path>");
```

Supported certificate formats: PEM, DER.

### Loading the Decryption Key <a name="loading-the-decryption-key"></a>

#### From a PKCS#12 Key Store

A `PrivateKey` object can be created from a PKCS#12 key store by calling `EncryptionUtils.loadDecryptionKey` the following way:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey(
                                    "<insert PKCS#12 key file path>", 
                                    "<insert key alias>", 
                                    "<insert key password>");
```

#### From an Unencrypted Key File

A `PrivateKey` object can be created from an unencrypted key file by calling `EncryptionUtils.loadDecryptionKey` the following way:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey("<insert key file path>");
```

Supported RSA key formats:
* PKCS#1 PEM (starts with "-----BEGIN RSA PRIVATE KEY-----")
* PKCS#8 PEM (starts with "-----BEGIN PRIVATE KEY-----")
* Binary DER-encoded PKCS#8

### Performing Payload Encryption and Decryption <a name="performing-payload-encryption-and-decryption"></a>

+ [Introduction](#introduction)
+ [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
+ [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)

#### Introduction <a name="introduction"></a>

This library supports two types of encryption/decryption, both of which support field level and entire payload encryption: JWE encryption and what the library refers to as Field Level Encryption (Mastercard encryption), a scheme used by many services hosted on Mastercard Developers before the library added support for JWE.

#### JWE Encryption and Decryption <a name="jwe-encryption-and-decryption"></a>

+ [Introduction](#jwe-introduction)
+ [Configuring the JWE Encryption](#configuring-the-jwe-encryption)
+ [Performing JWE Encryption](#performing-jwe-encryption)
+ [Performing JWE Decryption](#performing-jwe-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-payloads-jwe)
+ [Decrypting Entire Payloads](#decrypting-entire-payloads-jwe)
+ [Encrypting Payloads with Wildcards](#encrypting-wildcard-payloads-jwe)
+ [Decrypting Payloads with Wildcards](#decrypting-wildcard-payloads-jwe)

##### • Introduction <a name="jwe-introduction"></a>

This library uses [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) for the encryption of sensitive data.
The core methods responsible for payload encryption and decryption are `encryptPayload` and `decryptPayload` in the `JweEncryption` class.

* `encryptPayload` usage:
```java
String encryptedRequestPayload = JweEncryption.encryptPayload(requestPayload, config);

```

* `decryptPayload` usage:
```java
String responsePayload = JweEncryption.decryptPayload(encryptedResponsePayload, config);
```

##### • Configuring the JWE Encryption <a name="configuring-the-jwe-encryption"></a>
Use the `JweConfigBuilder` to create `JweConfig` instances. Example:
```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withDecryptionKey(decryptionKey)
    .withEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
    .withDecryptionPath("$.path.to.encryptedFoo.encryptedValue", "$.path.to.foo")
    .withEncryptedValueFieldName("encryptedValue")
    .build();
```

See also:
* [Service Configurations for Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)

##### • Performing JWE Encryption <a name="performing-jwe-encryption"></a>

Call `JweEncryption.encryptPayload` with a JSON request payload and a `JweConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
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
String encryptedPayload = JweEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
    "path": {
        "to": {
            "encryptedFoo": {
                "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
            }
        }
    }
}
```

##### • Performing JWE Decryption <a name="performing-jwe-decryption"></a>

Call `JweEncryption.decryptPayload` with a JSON response payload and a `JweConfig` instance.

Example using the configuration [above](#configuring-the-jwe-encryption):
```java
String encryptedPayload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"encryptedValue\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "            }" +
    "        }" +
    "    }" +
    "}";
String payload = JweEncryption.decryptPayload(encryptedPayload, config);
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

##### • Encrypting Entire Payloads <a name="encrypting-entire-payloads-jwe"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$", "$")
    // …
    .build();
```

Example:
```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = JweEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
    "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
}
```

##### • Decrypting Entire Payloads <a name="decrypting-entire-payloads-jwe"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.encryptedValue", "$")
    // …
    .build();
```

Example:
```java
String encryptedPayload = "{" +
    "  \"encryptedValue\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "}";
String payload = JweEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

##### • Encrypting Payloads with Wildcards <a name="encrypting-wildcard-payloads-jwe"></a>

Wildcards can be encrypted using the "[*]" operator as part of encryption path:

```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$.list[*]sensitiveField1", "$.list[*]encryptedField")
    // …
    .build();
```

Example:
```java
String payload = "{ \"list\": [ " +
    "   { \"sensitiveField1\" : \"sensitiveValue1\"}, "+
    "   { \"sensitiveField1\" : \"sensitiveValue2\"} " +
    "]}";
String encryptedPayload = JweEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
  "list": [
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"},
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm"}
  ]
}
```

##### • Decrypting Payloads with Wildcards <a name="decrypting-wildcard-payloads-jwe"></a>

Wildcards can be decrypted using the "[*]" operator as part of decryption path:

```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.list[*]encryptedField", "$.list[*]sensitiveField1")
    // …
    .build();
```

Example:
```java
String encryptedPayload = "{ \"list\": [ " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"}, " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm\"} " +
        " ]}";
String payload = JweEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
  "list": [
    {"sensitiveField1": "sensitiveValue1"},
    {"sensitiveField2": "sensitiveValue2"}
  ]
}
```

#### Mastercard Encryption and Decryption <a name="mastercard-encryption-and-decryption"></a>

+ [Introduction](#mastercard-introduction)
+ [Configuring the Mastercard Encryption](#configuring-the-mastercard-encryption)
+ [Performing Mastercard Encryption](#performing-mastercard-encryption)
+ [Performing Mastercard Decryption](#performing-mastercard-decryption)
+ [Encrypting Entire Payloads](#encrypting-entire-mastercard-payloads)
+ [Decrypting Entire Payloads](#decrypting-entire-mastercard-payloads)
+ [Encrypting Payloads with Wildcards](#encrypting-wildcard-mastercard-payloads)
+ [Decrypting Payloads with Wildcards](#decrypting-wildcard-mastercard-payloads)
+ [Using HTTP Headers for Encryption Params](#using-http-headers-for-encryption-params)

##### • Introduction <a name="mastercard-introduction"></a>
 
The core methods responsible for payload encryption and decryption are `encryptPayload` and `decryptPayload` in the `FieldLevelEncryption` class.

* `encryptPayload` usage:
```java
String encryptedRequestPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);

```

* `decryptPayload` usage:
```java
String responsePayload = FieldLevelEncryption.decryptPayload(encryptedResponsePayload, config);
```

##### • Configuring the Mastercard Encryption <a name="configuring-the-mastercard-encryption"></a>
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

See also:
* [FieldLevelEncryptionConfig.java](https://www.javadoc.io/page/com.mastercard.developer/client-encryption/latest/com/mastercard/developer/encryption/FieldLevelEncryptionConfig.html) for all config options
* [Service Configurations for Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)

##### • Performing Mastercard Encryption <a name="performing-mastercard-encryption"></a>

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
                "encryptedKey": "67f467d1b653d98411a0c6d3c…ffd4c09dd42f713a51bff2b48f937c8",
                "encryptedValue": "b73aabd267517fc09ed72455c2…dffb5fa04bf6e6ce9ade1ff514ed6141"
            }
        }
    }
}
```

##### • Performing Mastercard Decryption <a name="performing-mastercard-decryption"></a>

Call `FieldLevelEncryption.decryptPayload` with a JSON response payload and a `FieldLevelEncryptionConfig` instance.

Example using the configuration [above](#configuring-the-field-level-encryption):
```java
String encryptedPayload = "{" +
    "    \"path\": {" +
    "        \"to\": {" +
    "            \"encryptedFoo\": {" +
    "                \"iv\": \"e5d313c056c411170bf07ac82ede78c9\"," +
    "                \"encryptedKey\": \"e3a56746c0f9109d18b3a2652b76…f16d8afeff36b2479652f5c24ae7bd\"," +
    "                \"encryptedValue\": \"809a09d78257af5379df0c454dcdf…353ed59fe72fd4a7735c69da4080e74f\"" +
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

##### • Encrypting Entire Payloads <a name="encrypting-entire-mastercard-payloads"></a>

Entire payloads can be encrypted using the "$" operator as encryption path:

```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$", "$")
    // …
    .build();
```

Example:
```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
    "iv": "1b9396c98ab2bfd195de661d70905a45",
    "encryptedKey": "7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13",
    "encryptedValue": "e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515"
}
```

##### • Decrypting Entire Payloads <a name="decrypting-entire-mastercard-payloads"></a>

Entire payloads can be decrypted using the "$" operator as decryption path:

```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$", "$")
    // …
    .build();
```

Example:
```java
String encryptedPayload = "{" +
    "  \"iv\": \"1b9396c98ab2bfd195de661d70905a45\"," +
    "  \"encryptedKey\": \"7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13\"," +
    "  \"encryptedValue\": \"e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515\"" +
    "}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}

```
##### • Encrypting Payloads with Wildcards <a name="encrypting-wildcard-mastercard-payloads"></a>

Wildcards can be encrypted using the "[*]" operator as part of encryption path:

```java
FLEConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$.list[*]sensitiveField1", "$.list[*]encryptedField")
    // …
    .build();
```

Example:
```java
String payload = "{ \"list\": [ " +
    "   { \"sensitiveField1\" : \"sensitiveValue1\"}, "+
    "   { \"sensitiveField1\" : \"sensitiveValue2\"} " +
    "]}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
  "list": [
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"},
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm"}
  ]
}
```

##### • Decrypting Payloads with Wildcards <a name="decrypting-wildcard-mastercard-payloads"></a>

Wildcards can be decrypted using the "[*]" operator as part of decryption path:

```java
FLEConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.list[*]encryptedField", "$.list[*]sensitiveField1")
    // …
    .build();
```

Example:
```java
String encryptedPayload = "{ \"list\": [ " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"}, " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm\"} " +
        " ]}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
  "list": [
    {"sensitiveField1": "sensitiveValue1"},
    {"sensitiveField2": "sensitiveValue2"}
  ]
}
```

##### • Using HTTP Headers for Encryption Params <a name="using-http-headers-for-encryption-params"></a>

In the sections above, encryption parameters (initialization vector, encrypted symmetric key, etc.) are part of the HTTP payloads.

Here is how to configure the library for using HTTP headers instead.

###### Configuration for Using HTTP Headers <a name="configuration-for-using-http-headers"></a>

Call `with{Param}HeaderName` instead of `with{Param}FieldName` when building a `FieldLevelEncryptionConfig` instance. Example:
```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withDecryptionKey(decryptionKey)
    .withEncryptionPath("$", "$")
    .withDecryptionPath("$", "$")
    .withOaepPaddingDigestAlgorithm("SHA-256")
    .withEncryptedValueFieldName("data")
    .withIvHeaderName("x-iv")
    .withEncryptedKeyHeaderName("x-encrypted-key")
    // …
    .withFieldValueEncoding(FieldValueEncoding.HEX)
    .build();
```

See also:
* [FieldLevelEncryptionConfig.java](https://www.javadoc.io/page/com.mastercard.developer/client-encryption/latest/com/mastercard/developer/encryption/FieldLevelEncryptionConfig.html) for all config options
* [Service Configurations for Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)

###### Encrypting Using HTTP Headers

Encryption can be performed using the following steps:

1. Generate parameters by calling `FieldLevelEncryptionParams.generate`:

```java
FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
```

2. Update the request headers:

```java
request.setHeader(config.getIvHeaderName(), params.getIvValue());
request.setHeader(config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
// …
```

3. Call `encryptPayload` with params:
```java
FieldLevelEncryption.encryptPayload(payload, config, params);
```

Example using the configuration [above](#configuration-for-using-http-headers):

```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config, params);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Output:
```json
{
    "data": "53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5"
}
```

###### Decrypting Using HTTP Headers

Decryption can be performed using the following steps:

1. Read the response headers:

```java
String ivValue = response.getHeader(config.getIvHeaderName());
String encryptedKeyValue = response.getHeader(config.getEncryptedKeyHeaderName());
// …
```

2. Create a `FieldLevelEncryptionParams` instance:

```java
FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, …, config);
```

3. Call `decryptPayload` with params:
```java
FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);
```

Example using the configuration [above](#configuration-for-using-http-headers):

```java
String encryptedPayload = "{" +
    "  \"data\": \"53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5\"" +
    "}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Output:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The `com.mastercard.developer.interceptors` package will provide you with some interceptor classes you can use when configuring your API client. 
These classes will take care of encrypting request and decrypting response payloads, but also of updating HTTP headers when needed.

Library options currently supported for the `java` generator:
+ [okhttp-gson](#okhttp-gson)
+ [feign](#feign)
+ [retrofit](#retrofit)
+ [retrofit2](#retrofit2)
+ [google-api-client](#google-api-client)

See also:
* [OpenAPI Generator (maven Plugin)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-maven-plugin)
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [CONFIG OPTIONS for java](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/java.md)

#### okhttp-gson <a name="okhttp-gson"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>okhttp-gson</library>
    <!-- … -->
</configuration>
```

##### Usage of the `OkHttp2EncryptionInterceptor` (OpenAPI Generator 3.3.x)
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
List<Interceptor> interceptors = client.getHttpClient().interceptors();
interceptors.add(OkHttp2EncryptionInterceptor.from(config));
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = new ServiceApi(client);
// …
```

##### Usage of the `OkHttpEncryptionInterceptor` (OpenAPI Generator 4+)
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
client.setHttpClient(
    client.getHttpClient()
        .newBuilder()
        .addInterceptor(OkHttpEncryptionInterceptor.from(config))
        .addInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey))
        .build()
);
ServiceApi serviceApi = new ServiceApi(client);
// …
```

#### feign <a name="feign"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>feign</library>
    <!-- … -->
</configuration>
```

##### Usage of `OpenFeignEncoderExecutor` and `OpenFeignDecoderExecutor`
```java
ApiClient client = new ApiClient();
ObjectMapper objectMapper = client.getObjectMapper();
client.setBasePath("https://sandbox.api.mastercard.com");
Feign.Builder feignBuilder = client.getFeignBuilder();
ArrayList<RequestInterceptor> interceptors = new ArrayList<>();
interceptors.add(new OpenFeignOAuth1Interceptor(consumerKey, signingKey, client.getBasePath()));
feignBuilder.requestInterceptors(interceptors);
feignBuilder.encoder(OpenFeignEncoderExecutor.from(config, new FormEncoder(new JacksonEncoder(objectMapper))));
feignBuilder.decoder(OpenFeignDecoderExecutor.from(config, new JacksonDecoder(objectMapper)));
ServiceApi serviceApi = client.buildClient(ServiceApi.class);
// …
```

#### retrofit <a name="retrofit"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit</library>
    <!-- … -->
</configuration>
```

##### Usage of the `OkHttp2EncryptionInterceptor`
```java
ApiClient client = new ApiClient();
RestAdapter.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.setEndpoint("https://sandbox.api.mastercard.com"); 
List<Interceptor> interceptors = client.getOkClient().interceptors();
interceptors.add(OkHttp2EncryptionInterceptor.from(config));
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// …
```

#### retrofit2 <a name="retrofit2"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit2</library>
    <!-- … -->
</configuration>
```

##### Usage of the `OkHttpEncryptionInterceptor`
```java
ApiClient client = new ApiClient();
Retrofit.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.baseUrl("https://sandbox.api.mastercard.com"); 
OkHttpClient.Builder okBuilder = client.getOkBuilder();
okBuilder.addInterceptor(OkHttpEncryptionInterceptor.from(config));
okBuilder.addInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// …
```

#### google-api-client <a name="google-api-client"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>google-api-client</library>
    <!-- … -->
</configuration>
```

##### Usage of `HttpExecuteEncryptionInterceptor` and `HttpExecuteInterceptorChain`
```java
HttpRequestInitializer initializer = new HttpRequestInitializer() {
    @Override
    public void initialize(HttpRequest request) {
        HttpExecuteOAuth1Interceptor authenticationInterceptor = new HttpExecuteOAuth1Interceptor(consumerKey, signingKey);
        HttpExecuteEncryptionInterceptor encryptionInterceptor = HttpExecuteEncryptionInterceptor.from(config);
        request.setInterceptor(new HttpExecuteInterceptorChain(Arrays.asList(encryptionInterceptor, authenticationInterceptor)));
        request.setResponseInterceptor(encryptionInterceptor);
    }
};
ApiClient client = new ApiClient("https://sandbox.api.mastercard.com", null, initializer, null);
ServiceApi serviceApi = client.serviceApi();
// …
```
