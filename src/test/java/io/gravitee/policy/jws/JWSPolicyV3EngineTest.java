/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.jws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.jws.configuration.JWSPolicyConfiguration;
import io.gravitee.policy.jws.handler.ConfigurableStreamHandlerFactory;
import io.gravitee.policy.jws.handler.URLStreamHandler;
import io.gravitee.policy.jws.utils.JwsHeader;
import io.gravitee.policy.jws.v3.JWSPolicyV3;
import io.gravitee.policy.jws.validator.CRLValidator;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.core.env.Environment;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 * <p>
 * Working with JKS file
 * <p>
 * How to generate JKS KeyStore File
 * <p>
 * keytool -genkeypair \
 * -alias mytestkey \
 * -keyalg RSA \
 * -dname "CN=Web Server,OU=Unit,O=Organization,L=City,S=State,C=US" \
 * -keypass changeme \
 * -keystore server.jks \
 * -storepass letmein \
 * <p>
 * Export Public Key certificate DER format
 * keytool -exportcert -alias mytestkey -file public_key.der -keystore server.jks
 * <p>
 * Export PEM Public certificate
 * keytool -exportcert -rfc -file server.pem -keystore server.jks -alias mytestkey
 * <p>
 * Export Full PEM certificate
 * keytool -importkeystore -srckeystore server.jks \
 * -destkeystore server.p12 \
 * -srcstoretype jks \
 * -deststoretype pkcs12
 * openssl pkcs12 -in server.p12 -out server.pem
 * <p>
 * Get PEM information
 * openssl x509 -text -in server.pem
 */
@ExtendWith(MockitoExtension.class)
public class JWSPolicyV3EngineTest {

    private static final String KID = "MAIN";
    private static final String PUBLIC_KEY_PROPERTY = "policy.jws.kid.%s";

    private JWSPolicyV3 jwsPolicyV3;

    @Mock
    private PolicyChain policyChain;

    @Mock
    private ExecutionContext executionContext;

    @Mock
    private Environment environment;

    @Mock
    private JWSPolicyConfiguration configuration;

    @BeforeAll
    public static void setup() {
        // enable classpath URL
        ConfigurableStreamHandlerFactory configurableStreamHandlerFactory = ConfigurableStreamHandlerFactory.getInstance(
            "classpath",
            new URLStreamHandler()
        );
        configurableStreamHandlerFactory.setURLStreamHandlerFactory();
    }

    @BeforeEach
    public void init() {
        jwsPolicyV3 = new JWSPolicyV3(configuration);
    }

    @Test
    public void shouldTransformInput_validX5CHeader() throws Exception {
        String expected = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");
        String input = getJsonWebToken("public_key.der", true, null);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(configuration.isCheckCertificateValidity()).thenReturn(true);
        when(configuration.isCheckCertificateRevocation()).thenReturn(false);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getPublicKey());

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        assertThat(ret).isNotNull();

        JSONAssert.assertEquals(expected, ret.toString(), false);
    }

    @Test
    public void shouldTransformInput_validX5CHeader_pemFile() throws Exception {
        shouldTransformInput_validX5CHeader_withPemFile("server.pem");
    }

    @Test
    public void shouldTransformInput_validX5CHeader_fullPemFile() throws Exception {
        shouldTransformInput_validX5CHeader_withPemFile("full-server.pem");
    }

    @Test
    public void shouldTransformInput_validX5CHeader_wrongSignature() throws Exception {
        String input = getJsonWebToken("public_key.der", false, null);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getAbsoluteFilePath("full-server.pem"));

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        assertThat(ret).isNull();
    }

    @Test
    public void shouldTransformInput_malformedJWS() throws Exception {
        String input = loadResource("/io/gravitee/policy/jws/malformed-jws.json");

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        assertThat(ret).isNull();
    }

    @Test
    public void shouldTransformInout_wrongX5CHeader() throws Exception {
        String input = getJsonWebToken("wrong-public_key.der", true, null);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getPublicKey());

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        assertThat(ret).isNull();
    }

    @Test
    public void shouldTransformInout_wrongJOSETypeHeader() throws Exception {
        Map<String, Object> additionalHeaders = new HashMap<>();
        additionalHeaders.put(JwsHeader.TYPE, "WRONG_TYPE");
        String input = getJsonWebToken("public_key.der", true, additionalHeaders);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getPublicKey());

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        assertThat(ret).isNull();
    }

    @Test
    public void shouldTransformInout_wrongJOSECtyHeader() throws Exception {
        Map<String, Object> additionalHeaders = new HashMap<>();
        additionalHeaders.put(JwsHeader.CONTENT_TYPE, "wrongType");
        String input = getJsonWebToken("public_key.der", true, additionalHeaders);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getPublicKey());

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        assertThat(ret).isNull();
    }

    @Test
    public void shouldTransformInput__correctJOSEHeaders() throws Exception {
        String expected = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");
        Map<String, Object> additionalHeaders = new HashMap<>();
        additionalHeaders.put(JwsHeader.TYPE, "jose+json");
        additionalHeaders.put(JwsHeader.CONTENT_TYPE, "JSON");
        String input = getJsonWebToken("public_key.der", true, additionalHeaders);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(configuration.isCheckCertificateValidity()).thenReturn(true);
        when(configuration.isCheckCertificateRevocation()).thenReturn(false);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getPublicKey());

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        assertThat(ret).isNotNull();

        JSONAssert.assertEquals(expected, ret.toString(), false);
    }

    @Test
    public void shouldValidateCRL() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        String fileContent = getFileContent("cert-with-crl/certs/server-valid.crt");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(
            new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8))
        );
        jwsPolicyV3.validateCRLSFromCertificate(cert, null);
    }

    @Test
    public void shouldValidateCRL_certificateException() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        String fileContent = getFileContent("cert-with-crl/certs/server-revoked.crt");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(
            new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8))
        );

        CRLValidator.validateCRLSFromCertificate(cert, null).test().assertError(CertificateException.class);

        Exception exception = assertThrows(
            RuntimeException.class,
            () -> CRLValidator.validateCRLSFromCertificate(cert, null).blockingAwait()
        );
        String expectedMessage = "Certificate has been revoked";
        String actualMessage = exception.getCause().getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    private void shouldTransformInput_validX5CHeader_withPemFile(String pemFile) throws Exception {
        String expected = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");
        String input = getJsonWebToken("public_key.der", true, null);

        when(executionContext.getComponent(Environment.class)).thenReturn(environment);
        when(configuration.isCheckCertificateValidity()).thenReturn(true);
        when(configuration.isCheckCertificateRevocation()).thenReturn(false);
        when(environment.getProperty(String.format(PUBLIC_KEY_PROPERTY, KID))).thenReturn(getAbsoluteFilePath(pemFile));

        // Prepare context
        Buffer ret = jwsPolicyV3.map(executionContext, policyChain).apply(Buffer.buffer(input));
        assertThat(ret).isNotNull();

        JSONAssert.assertEquals(expected, ret.toString(), false);
    }

    /**
     * Return Json Web Token string value.
     *
     * @return String
     * @throws Exception
     */
    private String getJsonWebToken(String publicKeyDerFile, boolean useKeyPair, Map<String, Object> additionalHeaders) throws Exception {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("kid", KID);
        header.put("x5c", getPublicKeyCertificateX5CDERFormat(publicKeyDerFile));
        if (additionalHeaders != null) {
            header.putAll(additionalHeaders);
        }

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setHeader(header);
        String payload = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");
        jwtBuilder.setPayload(payload);

        jwtBuilder.signWith(SignatureAlgorithm.RS256, useKeyPair ? getPrivateKeyFromKeyPair() : getPrivateKeyFromDerFile());
        return jwtBuilder.compact();
    }

    /**
     * Get the RSA private key
     *
     * @return
     * @throws Exception
     */
    private PrivateKey getPrivateKeyFromKeyPair() throws Exception {
        return keyPair().getPrivate();
    }

    /**
     * Return string value of public key matching format ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)
     *
     * @return String
     * @throws IOException
     */
    public String getPublicKey() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        /* encode the "ssh-rsa" string */
        try {
            byte[] sshrsa = new byte[] { 0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a' };
            out.write(sshrsa);
            /* Encode the public exponent */
            BigInteger e = ((RSAPublicKey) keyPair().getPublic()).getPublicExponent();
            byte[] data = e.toByteArray();
            encodeUInt32(data.length, out);
            out.write(data);
            /* Encode the modulus */
            BigInteger m = ((RSAPublicKey) keyPair().getPublic()).getModulus();
            data = m.toByteArray();
            encodeUInt32(data.length, out);
            out.write(data);
            String publicKeyPrefix = "ssh-rsa ";
            String publicKeyPayload = Base64.getEncoder().encodeToString(out.toByteArray());
            String publicKeySuffix = " test@test.com";
            return publicKeyPrefix + publicKeyPayload + publicKeySuffix;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The "x5c" (X.509 certificate chain) Header Parameter contains the
     * X.509 public key certificate or certificate chain [RFC5280]
     * corresponding to the key used to digitally sign the JWS.
     *
     * @param publicKeyDerFile
     * @return
     * @throws Exception
     */
    private String[] getPublicKeyCertificateX5CDERFormat(String publicKeyDerFile) throws Exception {
        File file = new File(this.getClass().getResource(publicKeyDerFile).toURI());
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();
        String x5c = Base64.getEncoder().encodeToString(keyBytes);
        return new String[] { x5c };
    }

    private String getAbsoluteFilePath(String filePath) throws Exception {
        File file = new File(Objects.requireNonNull(this.getClass().getResource(filePath)).toURI());
        return file.getAbsolutePath();
    }

    private String getFileContent(String filePath) throws Exception {
        File file = new File(Objects.requireNonNull(this.getClass().getResource(filePath)).toURI());
        return Files.readString(Paths.get(file.getAbsolutePath()), StandardCharsets.UTF_8);
    }

    /**
     * Get KeyPair from jks file
     *
     * @return keyPair (RSA private/public key) from a jks file
     * @throws Exception
     */
    private KeyPair keyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(new File(this.getClass().getResource("server.jks").toURI())), "letmein".toCharArray());

        RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey("mytestkey", "changeme".toCharArray());
        RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
        return new KeyPair(publicKey, key);
    }

    /**
     * How to generate keys?
     * Run : ssh-keygen -t rsa -C "test.test@mycompany.com"
     * ==> Will create id_rsa & id_rsa.pub
     * Then run : openssl pkcs8 -topk8 -inform PEM -outform DER -in id_rsa -out private_key.der -nocrypt
     * ==> Will create private_key.der unsecured that can be used.
     *
     * @return
     * @throws Exception
     */
    private PrivateKey getPrivateKeyFromDerFile() throws Exception {
        File file = new File(this.getClass().getResource("private_key.der").toURI());
        FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) file.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }

    private String loadResource(String resource) {
        try (InputStream is = this.getClass().getResourceAsStream(resource)) {
            return new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private void encodeUInt32(int value, OutputStream out) throws IOException {
        byte[] tmp = new byte[4];
        tmp[0] = (byte) ((value >>> 24) & 0xff);
        tmp[1] = (byte) ((value >>> 16) & 0xff);
        tmp[2] = (byte) ((value >>> 8) & 0xff);
        tmp[3] = (byte) (value & 0xff);
        out.write(tmp);
    }
}
