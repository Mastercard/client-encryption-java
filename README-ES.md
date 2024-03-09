# client-encryption-java
[![](https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg)](https://developer.mastercard.com/)


[![](https://github.com/Mastercard/client-encryption-java/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/client-encryption-java/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_client-encryption-java&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_client-encryption-java)
[![](https://github.com/Mastercard/client-encryption-java/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/client-encryption-java/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/maven-central/v/com.mastercard.developer/client-encryption.svg)](https://search.maven.org/artifact/com.mastercard.developer/client-encryption/)
[![](https://www.javadoc.io/badge/com.mastercard.developer/client-encryption.svg?color=blue)](https://www.javadoc.io/doc/com.mastercard.developer/client-encryption)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/client-encryption-java/blob/master/LICENSE)


## Índice
- [Overview](#overview)
  * [Compatibilidad](#compatibility)
  * [Referencias](#references)
  * [Política de Versionamiento y Obsolescencia](#versioning)
- [Uso](#usage)
  * [Requisitos previos](#prerequisites)
  * [Añadir la Librería a tu Proyecto](#adding-the-library-to-your-project)
  * [Selección del JSON Engine](#selecting-a-json-engine)
  * [Carga del Certificado de Encriptación](#loading-the-encryption-certificate)
  * [Carga de la clave de Desencriptación](#loading-the-decryption-key)
  * [Realización de la Encriptación y Desencriptación de Payloads](#performing-payload-encryption-and-decryption)
    * [Introduction](#introduction)
    * [JWE Encryption and Decryption](#jwe-encryption-and-decryption)
    * [Mastercard Encryption and Decryption](#mastercard-encryption-and-decryption)
  * [Integración con Librerías de OpenAPI Generator API ](#integrating-with-openapi-generator-api-client-libraries)


## Overview <a name="overview"></a>
Librería para el cifrado y descifrado de datos conforme a la API de Mastercard.


### Compatibilidad <a name="compatibility"></a>
Java 11+


### Bibliografía/Referencias <a name="references"></a>
* [JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
* [Securing Sensitive Data Using Payload Encryption](https://developer.mastercard.com/platform/documentation/security-and-authentication/securing-sensitive-data-using-payload-encryption/)


### Política de versionamiento y obsolescencia <a name="versioning"></a>
* [](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)


## Uso <a name="usage"></a>
### Requisitos previos <a name="prerequisites"></a>
 Antes de usar esta librería, es necesario configurar el proyecto en el [Portal de Desarrolladores de Mastercard](https://developer.mastercard.com).


Como parte de esta configuración, recibirás:
* Un certificado público de encriptación de solicitudes ( Clave de Encriptación del Cliente).
* Una clave privada de desencriptación de respuestas (Clave de Encriptación de Mastercard).


### Añadir la librería a tu proyecto <a name="adding-the-library-to-your-project"></a>


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


#### Otros gestores de dependencias
Consultar: https://search.maven.org/artifact/com.mastercard.developer/client-encryption


### Seleccionar un motor JSON <a name="selecting-a-json-engine"></a>


Esta librería requiere que se agregue una de las siguientes dependencias a tu classpath:


* [Jackson](https://search.maven.org/artifact/com.fasterxml.jackson.core/jackson-databind) 2.4.5+
* [Google Gson](https://search.maven.org/artifact/com.google.code.gson/gson) 2.3.1+
* [Json-smart](https://search.maven.org/artifact/net.minidev/json-smart) 2.1.1+
* [Jettison](https://search.maven.org/artifact/org.codehaus.jettison/jettison) 1.0+
* [Org JSON](https://search.maven.org/artifact/org.json/json) 20070829+


Puedes dejar que la librería elija por ti, o forzar que se use una de las nombrados en concreto mediante el método  `withJsonEngine` de la clase `JsonParser`.
Un ejemplo puede ser el siguiente:


```java
JsonParser.withJsonEngine(new JettisonJsonEngine());
```


Motores disponibles:
* `GsonJsonEngine`
* `JacksonJsonEngine`
* `JettisonJsonEngine`
* `JsonOrgJsonEngine`
* `JsonSmartJsonEngine`


### Carga del Certificado de Encriptación <a name="loading-the-encryption-certificate"></a>


Un objeto`Certificate` se puede crear a partir de un archivo mediante `EncryptionUtils.loadEncryptionCertificate`:
```java
Certificate encryptionCertificate = EncryptionUtils.loadEncryptionCertificate("<insert certificate file path>");
```


Formatos de certificados admitidos: PEM, DER.


### Carga de la Clave de Desencriptación<a name="loading-the-decryption-key"></a>


#### Desde un Key Store (almacén de claves) PKCS#12


Un objeto `PrivateKey` se puede crear a partir de un Key Store (almacén) PKCS#12 llamando a `EncryptionUtils.loadDecryptionKey` de la siguiente manera:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey(
                                    "<insert PKCS#12 key file path>",
                                    "<insert key alias>",
                                    "<insert key password>");
```


#### Desde un Archivo de Clave no Encriptado


Un objeto`PrivateKey` se puede crear a partir de un archivo de clave no encriptado llamando a  `EncryptionUtils.loadDecryptionKey` de la siguiente manera:
```java
PrivateKey decryptionKey = EncryptionUtils.loadDecryptionKey("<insert key file path>");
```


Formatos de claves RSA admitidos:
* PKCS#1 PEM (empieza con "-----BEGIN RSA PRIVATE KEY-----")
* PKCS#8 PEM (empieza con "-----BEGIN PRIVATE KEY-----")
* Binary DER-encoded PKCS#8


### Proceso de Encriptación y Desencriptación de Payload  <a name="performing-payload-encryption-and-decryption"></a>


+ [Introducción](#introduction)
+ [ Encriptación y Desencriptación JWE](#jwe-encryption-and-decryption)
+ [Encriptación y Desencriptación Mastercard ](#mastercard-encryption-and-decryption)


#### Introducción <a name="introduction"></a>


Esta librería admite dos tipos de encriptación/desencriptación, ambos compatibles con la encriptación field level y payload: encriptación JWE y lo que la librería denomina como Encriptación de Field Level(encriptación Mastercard), un esquema utilizado por muchos servicios alojados en Mastercard Developers antes de que la biblioteca agregara soporte para JWE.


#### Encriptación y desencriptación JWE <a name="jwe-encryption-and-decryption"></a>


+ [Introducción](#jwe-introduction)
+ [Configuración de la Encriptación JWE](#configuring-the-jwe-encryption)
+ [Realización de la Encriptación JWE](#performing-jwe-encryption)
+ [Realización de la Desencriptación JWE](#performing-jwe-decryption)
+ [Encriptación de Payloads completos](#encrypting-entire-payloads-jwe)
+ [Desencriptación de Payloads completos](#decrypting-entire-payloads-jwe)
+ [Encriptación de payloads con Wildcards](#encrypting-wildcard-payloads-jwe)
+ [Desencriptación de Payloads con Wildcards](#decrypting-wildcard-payloads-jwe)


##### • Introducción <a name="jwe-introduction"></a>


Esta librería usa[serialización compacta JWE](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1) para la encriptación de datos sensibles. Los métodos principales responsables de la encriptación y desencriptación del payload son `encryptPayload` y `decryptPayload` in contenidos en la clase`JweEncryption`.


* Uso de `encryptPayload` :
```java
String encryptedRequestPayload = JweEncryption.encryptPayload(requestPayload, config);


```


*Uso de  `decryptPayload` :
```java
String responsePayload = JweEncryption.decryptPayload(encryptedResponsePayload, config);
```


##### • Configuración de la Encriptación JWE  <a name="configuring-the-jwe-encryption"></a>
Utiliza  `JweConfigBuilder` para crear instancias de  `JweConfig`. Por ejemplo:
```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withDecryptionKey(decryptionKey)
    .withEncryptionPath("$.path.to.foo", "$.path.to.encryptedFoo")
    .withDecryptionPath("$.path.to.encryptedFoo.encryptedValue", "$.path.to.foo")
    .withEncryptedValueFieldName("encryptedValue")
    .build();
```


Consultar también:
* [Servicio de Configuración para Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)


##### • Realización de Encriptación JWE <a name="performing-jwe-encryption"></a>


LLama al método `JweEncryption.encryptPayload` con un payload de soicitud JSON y una isntancia de  `JweConfig`.


Ejemplo utilizando la configuración [de arriba](#configuring-the-jwe-encryption):
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


Salida:
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


##### • Realización de Desencriptación JWE  <a name="performing-jwe-decryption"></a>


Llama a `JweEncryption.decryptPayload` con un payload de respuesta JSON y una instancia de`JweConfig` .


Ejemplo usando la configuración de [arriba](#configuring-the-jwe-encryption):
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


Salida:
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


##### • Encriptación de Payloads Completos <a name="encrypting-entire-payloads-jwe"></a>


Los payloads completos pueden ser encriptados utilizando el operador “$” como ruta de encriptación (encryption path):


```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$", "$")
    // …
    .build();
```


Por ejemplo:
```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = JweEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```


Salida:
```json
{
    "encryptedValue": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"
}
```


##### • Desencriptación de Payloads Completos <a name="decrypting-entire-payloads-jwe"></a>


Los payloads completos pueden ser desencriptados utilizando el operador “$” como ruta de desencriptación:


```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.encryptedValue", "$")
    // …
    .build();
```


Por ejemplo:
```java
String encryptedPayload = "{" +
    "  \"encryptedValue\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"" +
    "}";
String payload = JweEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```


Salida:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```


##### • Encriptación de Payloads con Wildcards <a name="encrypting-wildcard-payloads-jwe"></a>


Los Wildcards pueden ser encriptados usando el operador "[*]" como parte de la ruta de encriptación:


```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$.list[*]sensitiveField1", "$.list[*]encryptedField")
    // …
    .build();
```


Por ejemplo:
```java
String payload = "{ \"list\": [ " +
    "   { \"sensitiveField1\" : \"sensitiveValue1\"}, "+
    "   { \"sensitiveField1\" : \"sensitiveValue2\"} " +
    "]}";
String encryptedPayload = JweEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```


Salida:
```json
{
  "list": [
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"},
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm"}
  ]
}
```


##### • Desencriptación de Payloads con Wildcards <a name="decrypting-wildcard-payloads-jwe"></a>


Los Wildcards pueden ser desencriptados usando el operador "[*]" como parte de la ruta de encriptación:


```java
JweConfig config = JweConfigBuilder.aJweEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.list[*]encryptedField", "$.list[*]sensitiveField1")
    // …
    .build();
```


Por ejemplo:
```java
String encryptedPayload = "{ \"list\": [ " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"}, " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm\"} " +
        " ]}";
String payload = JweEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```


Salida:
```json
{
  "list": [
    {"sensitiveField1": "sensitiveValue1"},
    {"sensitiveField2": "sensitiveValue2"}
  ]
}
```


#### Encriptación y Desencriptación de Mastercard<a name="mastercard-encryption-and-decryption"></a>


+ [Introducción](#mastercard-introduction)
+ [Configuración de la Encriptación de Mastercard](#configuring-the-mastercard-encryption)
+ [Realizacioón de la Encriptación de Mastercard](#performing-mastercard-encryption)
+ [Realizacioón de la Desencriptación de Mastercard](#performing-mastercard-decryption)
+ [Encriptación de Payloads Completos](#encrypting-entire-mastercard-payloads)
+ [Desencriptación de Payloads Completos](#decrypting-entire-mastercard-payloads)
+ [Encriptación de Payloads con Wildcards](#encrypting-wildcard-mastercard-payloads)
+ [Desencriptación de Payloads con Wildcards](#decrypting-wildcard-mastercard-payloads)
+ [Uso de cabeceras HTTP para los parámetros de Encriptación](#using-http-headers-for-encryption-params)


##### • Introducción <a name="mastercard-introduction"></a>
 
The core methods responsible for payload encryption and decryption are `encryptPayload` and `decryptPayload` in the `FieldLevelEncryption` class.


* Uso de`encryptPayload`:
```java
String encryptedRequestPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);


```


* Uso de  `decryptPayload`:
```java
String responsePayload = FieldLevelEncryption.decryptPayload(encryptedResponsePayload, config);
```


##### • Configuración de la Encriptación de Mastercard <a name="configuring-the-mastercard-encryption"></a>
Usa `FieldLevelEncryptionConfigBuilder` para crear instancias de `FieldLevelEncryptionConfig`. Por ejemplo:
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


Consultar también:
* [FieldLevelEncryptionConfig.java](https://www.javadoc.io/page/com.mastercard.developer/client-encryption/latest/com/mastercard/developer/encryption/FieldLevelEncryptionConfig.html) para todas las opciones de configuración
* [Service Configurations for Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)


##### • Realización de la Encriptación de Mastercard <a name="performing-mastercard-encryption"></a>


LLama a `FieldLevelEncryption.encryptPayload` con un payload de solicitud JSON y una instancia de `FieldLevelEncryptionConfig` .


Ejeplo usando la configuración de [arriba](#configuring-the-field-level-encryption):
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


Salida:
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


##### • Realización de la Desencriptación de Mastercard <a name="performing-mastercard-decryption"></a>


LLama a`FieldLevelEncryption.decryptPayload` con un payload de respuesta JSON y una instancia de `FieldLevelEncryptionConfig`.


Ejmplo usando la configuración de [arriba](#configuring-the-field-level-encryption):
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


Salida:
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


DIVISION  
===================================================================



##### • Encriptación de payload(mensajes) completos <a name="encrypting-entire-mastercard-payloads"></a>

Los payloads(mensajes) completos pueden ser encriptados mediante el operador "$" como ruta de encriptación:

```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$", "$")
    // …
    .build();
```

Ejemplo:
```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Salida:
```json
{
    "iv": "1b9396c98ab2bfd195de661d70905a45",
    "encryptedKey": "7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13",
    "encryptedValue": "e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515"
}
```

##### • Desencriptación de payloads(mensajes) completos <a name="decrypting-entire-mastercard-payloads"></a>

Los payloads(mensajes) completos pueden ser desencriptados mediante el operador "$" como ruta de desencriptación:

```java
FieldLevelEncryptionConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$", "$")
    // …
    .build();
```

Ejemplo:
```java
String encryptedPayload = "{" +
    "  \"iv\": \"1b9396c98ab2bfd195de661d70905a45\"," +
    "  \"encryptedKey\": \"7d5112fa08e554e3dbc455d0628…52e826dd10311cf0d63bbfb231a1a63ecc13\"," +
    "  \"encryptedValue\": \"e5e9340f4d2618d27f8955828c86…379b13901a3b1e2efed616b6750a90fd379515\"" +
    "}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Salida:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}

```
##### • Encriptando mensajes con WildCards(comodines) <a name="encrypting-wildcard-mastercard-payloads"></a>

Las Wildcards pueden ser encriptadas usando el operador "[*]" como parte de la ruta de encriptación:

```java
FLEConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withEncryptionCertificate(encryptionCertificate)
    .withEncryptionPath("$.list[*]sensitiveField1", "$.list[*]encryptedField")
    // …
    .build();
```

Ejemplo:
```java
String payload = "{ \"list\": [ " +
    "   { \"sensitiveField1\" : \"sensitiveValue1\"}, "+
    "   { \"sensitiveField1\" : \"sensitiveValue2\"} " +
    "]}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Salida:
```json
{
  "list": [
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw"},
    {"encryptedField": "eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm"}
  ]
}
```

##### • Desencriptando mensajes con WildCards(comodines) <a name="decrypting-wildcard-mastercard-payloads"></a>

Las Wildcards pueden ser desencriptadas usando el  operador "[*]" como parte de la ruta de desencriptación:

```java
FLEConfig config = FieldLevelEncryptionConfigBuilder.aFieldLevelEncryptionConfig()
    .withDecryptionKey(decryptionKey)
    .withDecryptionPath("$.list[*]encryptedField", "$.list[*]sensitiveField1")
    // …
    .build();
```

Ejemplo:
```java
String encryptedPayload = "{ \"list\": [ " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+oPYKZEMTKyYcSIVEgtQw\"}, " +
        " { \"encryptedField\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM….Y+asdvarvasdvfdvakmkmm\"} " +
        " ]}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```

Salida:
```json
{
  "list": [
    {"sensitiveField1": "sensitiveValue1"},
    {"sensitiveField2": "sensitiveValue2"}
  ]
}
```

##### • Usando cabeceras HTTP  para parámetros de encriptación. <a name="using-http-headers-for-encryption-params"></a>

En las secciones anteriores, los parámetros de encriptación (clave simétrica encriptada,vector de inicialización,etc.)  son parte de los datos contenidos en los mensajes HTTP.

Aquí se explica como configurar la librería para usar las cabeceras HTTP en su lugar.

###### Configuración para usar cabeceras HTTP <a name="configuration-for-using-http-headers"></a>

Llama a `with{Param}HeaderName` en vez de a `with{Param}FieldName` cuando crees una instancia `FieldLevelEncryptionConfig`. Por ejemplo:
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

Mirar también:
* [FieldLevelEncryptionConfig.java](https://www.javadoc.io/page/com.mastercard.developer/client-encryption/latest/com/mastercard/developer/encryption/FieldLevelEncryptionConfig.html) para ver todas las opciones de configuración
* [Service Configurations for Client Encryption Java](https://github.com/Mastercard/client-encryption-java/wiki/Service-Configurations-for-Client-Encryption-Java)

###### Encriptación usando cabeceras HTTP

El encriptado se puede llevar a cabo siguiendo los siguientes pasos:

1. Generar parámetros llamando a `FieldLevelEncryptionParams.generate`:

```java
FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
```

2. Actualizar los encabezados de la solicitud:

```java
request.setHeader(config.getIvHeaderName(), params.getIvValue());
request.setHeader(config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
// …
```

3. Llama a `encryptPayload` con parámetros:
```java
FieldLevelEncryption.encryptPayload(payload, config, params);
```

Ejemplo usando la configuración [anterior](#configuration-for-using-http-headers):

```java
String payload = "{" +
    "    \"sensitiveField1\": \"sensitiveValue1\"," +
    "    \"sensitiveField2\": \"sensitiveValue2\"" +
    "}";
String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config, params);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(encryptedPayload)));
```

Salida:
```json
{
    "data": "53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5"
}
```



DIVISION    
=====================================================================



###### Desencriptar usando cabeceras HTTP


Para desencriptar realizaremos los siguientes pasos:


1. Leer las cabeceras de la respuesta:


```java
String ivValue = response.getHeader(config.getIvHeaderName());
String encryptedKeyValue = response.getHeader(config.getEncryptedKeyHeaderName());
// …
```


2. Crear una instancia de `FieldLevelEncryptionParams` :


```java
FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, …, config);
```


3. Llamar a `decryptPayload` wcon "params":
```java
FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);
```


Ejemplo usando la configuración mostrada [encima](#configuration-for-using-http-headers):


```java
String encryptedPayload = "{" +
    "  \"data\": \"53b5f07ee46403af2e92abab900853…d560a0a08a1ed142099e3f4c84fe5e5\"" +
    "}";
String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);
System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(payload)));
```


Salida:
```json
{
    "sensitiveField1": "sensitiveValue1",
    "sensitiveField2": "sensitiveValue2"
}
```


### Integración con librerías de cliente para la API de OpenAPI Generator <a name="integrating-with-openapi-generator-api-client-libraries"></a>


[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) genera librerías de cliente para APIs siguiendo las [especificaciones de OpenAPI](https://github.com/OAI/OpenAPI-Specification).
Proporciona generadores y plantillas de bibliotecas para admitir múltiples lenguajes y frameworks.


El paquete `com.mastercard.developer.interceptors` te proporcionará algunos interceptores que puedes usar cuando configures tu cliente de APIs.
Estos se encargarán de encriptar las peticiones y desencriptar las respuestas, así como de actualizar las cabeceras HTTP cuando sea necesario.




Opciones de librerías soportadas por el generador de `java`:
+ [okhttp-gson](#okhttp-gson)
+ [feign](#feign)
+ [retrofit](#retrofit)
+ [retrofit2](#retrofit2)
+ [google-api-client](#google-api-client)


Ver también:
* [OpenAPI Generator (maven Plugin)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-maven-plugin)
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [CONFIG OPTIONS for java](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/java.md)


#### okhttp-gson <a name="okhttp-gson"></a>
##### Configuración del plugin de OpenAPI Generator
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>okhttp-gson</library>
    <!-- … -->
</configuration>
```


##### Uso de `OkHttp2EncryptionInterceptor` (OpenAPI Generator 3.3.x)
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
List<Interceptor> interceptors = client.getHttpClient().interceptors();
interceptors.add(OkHttp2EncryptionInterceptor.from(config));
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = new ServiceApi(client);
// …
```


##### Uso de `OkHttpEncryptionInterceptor` (OpenAPI Generator 4+)
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
##### Configuración del plugin de OpenAPI Generator
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>feign</library>
    <!-- … -->
</configuration>
```


##### Uso de `OpenFeignEncoderExecutor` y `OpenFeignDecoderExecutor`
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
##### Configuración del plugin de OpenAPI Generator
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit</library>
    <!-- … -->
</configuration>
```


##### Uso de `OkHttp2EncryptionInterceptor`
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
##### Configuración del plugin de OpenAPI Generator
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit2</library>
    <!-- … -->
</configuration>
```


##### Uso de `OkHttpEncryptionInterceptor`
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
##### Configuración del plugin de OpenAPI Generator
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>google-api-client</library>
    <!-- … -->
</configuration>
```


##### Uso de `HttpExecuteEncryptionInterceptor` y `HttpExecuteInterceptorChain`
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


