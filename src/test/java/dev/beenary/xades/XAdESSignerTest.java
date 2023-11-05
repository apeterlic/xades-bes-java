package dev.beenary.xades;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Contains tests for XMl signing and verification.
 *
 * @author Ana Peterlić
 */
class XAdESSignerTest {


    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        org.apache.xml.security.Init.init();
    }

    @Test
    void testXmlSigning() throws Exception {
        final byte[] encoded = this.getClass().getResourceAsStream("/xades/correct-message.xml").readAllBytes();
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");

        final String certificateFilePath = getResourceFileAsString("/certificate.cer");
        final String privateKeyFilePath = getResourceFileAsString("/privatekey.pem");
        String privateKeyPassword = "password";
        final XAdESSigner signer = new XAdESSigner(certificateFilePath, privateKeyFilePath, privateKeyPassword);
        final List<X509Certificate> certificateList = List.of(signer.loadCertificateFile());
        final Document signed = signer.sign(encoded);
        final XAdESVerifier verifier = new XAdESVerifier();
        boolean valid = verifier.verify(signed, certificateList);
        Assertions.assertTrue(valid);
    }


    String getResourceFileAsString(String fileName) throws URISyntaxException {
        final URL resource = XAdESSignerTest.class.getResource(fileName);
        return Paths.get(resource.toURI()).toAbsolutePath().toString();
    }

    @Test
    void testXmlSigning1() throws Exception {
        final byte[] encoded = this.getClass().getResourceAsStream("/xades/unsigned.xml").readAllBytes();
        final XAdESSigner signer = new XAdESSigner("keystore.jks", "password", "selfsigned");
        final Document signed = signer.sign(encoded);
        final XAdESVerifier verifier = new XAdESVerifier();
        // boolean valid = verifier.validate(signed);
        //Assertions.assertTrue(valid);
    }

}