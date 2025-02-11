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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gravitee.policy.jws.utils.CertUtils.getJsonWebToken;
import static io.vertx.core.http.HttpMethod.POST;
import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.policy.jws.handler.ConfigurableStreamHandlerFactory;
import io.gravitee.policy.jws.handler.URLStreamHandler;
import io.gravitee.policy.jws.v3.JWSPolicyV3;
import io.vertx.rxjava3.core.buffer.Buffer;
import io.vertx.rxjava3.core.http.HttpClient;
import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

@DeployApi({ "/apis/v3/jws.json", "/apis/v3/jws-checkCertificateRevocation.json" })
public class JWSPolicyV3EngineIntegrationTest extends V3EngineTest {

    private static final String KID = "MAIN";

    private ListAppender<ILoggingEvent> listAppender;

    @BeforeAll
    static void setup() {
        // enable classpath URL
        ConfigurableStreamHandlerFactory configurableStreamHandlerFactory = ConfigurableStreamHandlerFactory.getInstance(
            "classpath",
            new URLStreamHandler()
        );
        configurableStreamHandlerFactory.setURLStreamHandlerFactory();
    }

    @BeforeEach
    public void beforeEach() {
        // get Logback Logger
        Logger logger = (Logger) LoggerFactory.getLogger(JWSPolicyV3.class);

        // create and start a ListAppender
        listAppender = new ListAppender<>();
        listAppender.start();

        // add the appender to the logger
        // addAppender is outdated now
        logger.addAppender(listAppender);
    }

    @Test
    void should_unauthorized_empty_body(HttpClient client) {
        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer()))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    .containsExactly("Unable to decode JWS token. JWT String argument cannot be null or empty.", Level.ERROR);

                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_unauthorized_malformed_JWS(HttpClient client) throws Exception {
        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer("malformedJWS")))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    .containsExactly(
                        "Unable to decode JWS token. JWT strings must contain exactly 2 period characters. Found: 0",
                        Level.ERROR
                    );

                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_unauthorized_invalid_JWT_with_different_public_key(HttpClient client) throws Exception {
        wiremock.stubFor(post("/endpoint").willReturn(ok("Response from backend")));

        String input = getJsonWebToken(
            "/io/gravitee/policy/jws/server-bad.crt",
            "/io/gravitee/policy/jws/cert-with-crl/certs/server.key.pem",
            KID
        );
        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    .containsExactly(
                        "Unable to decode JWS token. Certificate public key modulus is different compare to the given public key modulus",
                        Level.ERROR
                    );

                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_unauthorized_invalid_JWT_with_different_signature(HttpClient client) throws Exception {
        wiremock.stubFor(post("/endpoint").willReturn(ok("Response from backend")));

        String input = getJsonWebToken(
            "/io/gravitee/policy/jws/cert-with-crl/certs/server-valid.crt",
            "/io/gravitee/policy/jws/other-server.key.pem",
            KID
        );
        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    .containsExactly(
                        "Unable to decode JWS token. JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                        Level.ERROR
                    );

                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_validate_JWS(HttpClient client) throws Exception {
        wiremock.stubFor(post("/endpoint").willReturn(ok("Response from backend")));

        String input = getJsonWebToken(
            // revoked or valid works because we don't check certificate revocation with policy checkCertificateRevocation option
            "/io/gravitee/policy/jws/cert-with-crl/certs/server-revoked.crt",
            "/io/gravitee/policy/jws/cert-with-crl/certs/server.key.pem",
            KID
        );

        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Response from backend");
                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_unauthorized_expired_certificate(HttpClient client) throws Exception {
        String input = getJsonWebToken(
            "/io/gravitee/policy/jws/cert-with-crl/certs/server-expired.crt",
            "/io/gravitee/policy/jws/cert-with-crl/certs/server.key.pem",
            KID
        );

        client
            .rxRequest(POST, "/test")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    // Note: Depending on the timezone, the date can be different
                    .anyMatch(l -> ((String) l).matches("Unable to decode JWS token. NotAfter: Fri Jan 01 .*"))
                    .contains(Level.ERROR);
                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_validate_JWS_with_check_certificate_revocation(HttpClient client) throws Exception {
        wiremock.stubFor(post("/endpoint").willReturn(ok("Response from backend")));

        String input = getJsonWebToken(
            "/io/gravitee/policy/jws/cert-with-crl/certs/server-valid.crt",
            "/io/gravitee/policy/jws/cert-with-crl/certs/server.key.pem",
            KID
        );

        client
            .rxRequest(POST, "/test-checkCertificateRevocation")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Response from backend");
                return true;
            })
            .assertNoErrors();
    }

    @Test
    void should_unauthorized_JWS_with_revoked_certificate(HttpClient client) throws Exception {
        String input = getJsonWebToken(
            "/io/gravitee/policy/jws/cert-with-crl/certs/server-revoked.crt",
            "/io/gravitee/policy/jws/cert-with-crl/certs/server.key.pem",
            KID
        );

        client
            .rxRequest(POST, "/test-checkCertificateRevocation")
            .flatMap(request -> request.rxSend(Buffer.buffer(input)))
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                return response.body().toFlowable();
            })
            .test()
            .awaitDone(30, TimeUnit.SECONDS)
            .assertComplete()
            .assertValue(body -> {
                assertThat(body).hasToString("Unauthorized");

                final List<ILoggingEvent> logList = listAppender.list;
                assertThat(logList)
                    .hasSize(1)
                    .element(0)
                    .extracting(ILoggingEvent::getFormattedMessage, ILoggingEvent::getLevel)
                    .containsExactly("Unable to decode JWS token. Certificate has been revoked", Level.ERROR);

                return true;
            })
            .assertNoErrors();
    }
}
