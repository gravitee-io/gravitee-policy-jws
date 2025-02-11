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

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.stream.exception.TransformationException;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.policy.jws.configuration.JWSPolicyConfiguration;
import io.gravitee.policy.jws.v3.JWSPolicyV3;
import io.gravitee.policy.jws.validator.CRLValidator;
import io.reactivex.rxjava3.core.Completable;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;

@Slf4j
public class JWSPolicy extends JWSPolicyV3 implements HttpPolicy {

    public JWSPolicy(final JWSPolicyConfiguration jwsPolicyConfiguration) {
        super(jwsPolicyConfiguration);
    }

    @Override
    public String id() {
        return "jws";
    }

    @Override
    public Completable onRequest(HttpPlainExecutionContext ctx) {
        Environment environment = ctx.getComponent(Environment.class);
        return ctx
            .request()
            .bodyOrEmpty()
            .flatMapCompletable(buffer -> validateJsonWebTokenRx(buffer.toString(), environment))
            .onErrorResumeNext(th ->
                switch (th.getClass().getSimpleName()) {
                    case "UnsupportedJwtException",
                        "ExpiredJwtException",
                        "MalformedJwtException",
                        "SignatureException",
                        "IllegalArgumentException",
                        "CertificateException",
                        "CertificateExpiredException" -> {
                        log.error("Unable to decode JWS token. {}", th.getMessage(), th);
                        yield ctx.interruptWith(new ExecutionFailure(HttpStatusCode.UNAUTHORIZED_401).message("Unauthorized"));
                    }
                    default -> {
                        log.error("Error occurs while decoding JWS token", th);
                        yield Completable.error(new TransformationException("Unable to apply JWS decode: " + th.getMessage(), th));
                    }
                }
            );
    }

    /**
     * 1 : decode jwt with the given gravitee.yml public key
     * 2 : check if typ header is present and equals to the specified values (currently JSON and JOSE+JSON)
     * 3 : check if cty header is present and equals to the specified values (currently json)
     * 4 : retrieve certificate from x5c JWS Header
     * The certificate or certificate chain is represented as a JSON array of
     * certificate value strings.  Each string in the array is base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
     * 5 : Extract certificate from X5C JWSHeader
     * 6 : compare certificate public key with given public key
     * 7 : check certificate validity (not before and not after settings)
     * 8 : check if certificate has been revoked via the certificate revocation list (CRL)
     *
     * @param jwt String Json Web Token
     * @return DefaultClaims claims extracted from JWT body
     */
    protected Completable validateJsonWebTokenRx(String jwt, Environment environment) throws CertificateException {
        var token = decodeJwt(jwt, environment);
        checkTypeHeader(token);
        checkCtyHeader(token);

        String[] x5c = retrieveCertificate(token);
        X509Certificate cert = extractCertificateFromX5CHeader(x5c);

        verifyPublicKey(environment, token, cert);

        if (jwsPolicyConfiguration.isCheckCertificateValidity()) {
            cert.checkValidity();
        }

        if (jwsPolicyConfiguration.isCheckCertificateRevocation()) {
            return CRLValidator.validateCRLSFromCertificate(cert, null);
        }
        return Completable.complete();
    }
}
