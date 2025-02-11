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
package io.gravitee.policy.jws.validator;

import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Flowable;
import io.reactivex.rxjava3.core.Maybe;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CRLValidator {

    private static final Logger logger = LoggerFactory.getLogger(CRLValidator.class);

    public static Completable validateCRLSFromCertificate(X509Certificate certificate, BigInteger serialNumber) {
        byte[] crlDistributionPointDerEncodedArray = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlDistributionPointDerEncodedArray == null) {
            return Completable.error(new CertificateException("Failed to find CRL distribution points for the given certificate"));
        }

        CRLDistPoint distPoint = getCRLDistPoint(crlDistributionPointDerEncodedArray);
        return Flowable
            .fromArray(distPoint.getDistributionPoints())
            .map(DistributionPoint::getDistributionPoint)
            .filter(dpn -> dpn.getType() == DistributionPointName.FULL_NAME)
            .map(dpn -> GeneralNames.getInstance(dpn.getName()).getNames())
            .flatMap(Flowable::fromArray)
            .map(generalName -> checkIfRevokedCertificate(certificate, generalName, serialNumber))
            .flatMap(Maybe::toFlowable)
            .filter(revoked -> revoked)
            .map(revoked -> {
                logger.info("Revoked certificate found");
                return Completable.error(new CertificateException("Certificate has been revoked"));
            })
            .flatMapCompletable(next -> Completable.complete().andThen(next));
    }

    private static Maybe<Boolean> checkIfRevokedCertificate(X509Certificate certificate, GeneralName generalName, BigInteger serialNumber) {
        return Maybe.fromCallable(() -> {
            String urlString = DERIA5String.getInstance(generalName.getName()).getString();
            X509CRL crl;

            // Open the URL connection and get the CRL stream
            URL url = new URL(urlString);
            URLConnection connection = url.openConnection();
            var inStream = new DataInputStream(connection.getInputStream());

            // Generate the CRL from the input stream
            crl = (X509CRL) certificateFactory().generateCRL(inStream);

            // Check if the certificate is revoked
            var revokedCertificate = crl.getRevokedCertificate(serialNumber != null ? serialNumber : certificate.getSerialNumber());
            return revokedCertificate != null;
        });
    }

    private static CRLDistPoint getCRLDistPoint(byte[] crlDistributionPointDerEncodedArray) {
        DEROctetString dosCrlDP = convertToDEROctetString(crlDistributionPointDerEncodedArray);
        byte[] crldpExtOctets = dosCrlDP.getOctets();
        ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
        ASN1Primitive derObj2;
        try {
            derObj2 = oAsnInStream2.readObject();
            oAsnInStream2.close();
        } catch (IOException e) {
            logger.error("Failed to get CRL distribution points", e);
            throw new RuntimeException(e);
        }
        return CRLDistPoint.getInstance(derObj2);
    }

    private static DEROctetString convertToDEROctetString(byte[] crlDistributionPointDerEncodedArray) {
        ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray));
        ASN1Primitive derObjCrlDP;
        try {
            derObjCrlDP = oAsnInStream.readObject();
            oAsnInStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return (DEROctetString) derObjCrlDP;
    }

    public static CertificateFactory certificateFactory() throws CertificateException {
        return CertificateFactory.getInstance("X.509");
    }
}
