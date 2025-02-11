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
package io.gravitee.policy.jws.utils;

import static io.gravitee.policy.jws.utils.ResourceUtils.loadResource;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.bouncycastle.util.io.pem.PemReader;

public class CertUtils {

    /**
     * Return Json Web Token string value.
     * @return String
     * @throws Exception
     */
    public static String getJsonWebToken(String publicKeyCrtFile, String privateKeyPemFile, String KID) throws Exception {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("kid", KID);
        header.put("x5c", getPublicKeyCertificateX5CCRTFormat(publicKeyCrtFile));

        JwtBuilder jwtBuilder = Jwts.builder();
        jwtBuilder.setHeader(header);
        String payload = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");
        jwtBuilder.setPayload(payload);

        jwtBuilder.signWith(SignatureAlgorithm.RS256, getPrivateKeyFromPEMFile(privateKeyPemFile));
        return jwtBuilder.compact();
    }

    private static String[] getPublicKeyCertificateX5CCRTFormat(String publicKeyCrtFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(CertUtils.class.getResourceAsStream(publicKeyCrtFile));

        String x5c = Base64.getEncoder().encodeToString(cert.getEncoded());
        return new String[] { x5c };
    }

    private static PrivateKey getPrivateKeyFromPEMFile(String privateKeyPemFile) throws Exception {
        File file = new File(Objects.requireNonNull(ResourceUtils.class.getResource(privateKeyPemFile)).toURI());
        FileReader keyReader = new FileReader(file);
        PemReader pemReader = new PemReader(keyReader);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }
}
