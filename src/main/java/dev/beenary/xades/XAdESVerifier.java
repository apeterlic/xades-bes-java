package dev.beenary.xades;

import dev.beenary.util.XAdESUtil;
import dev.beenary.util.Defense;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Class for XAdES XMl signature verification.
 *
 * @author Ana Peterlić
 */
public class XAdESVerifier implements Verifier {

    private PublicKey currentPublicKey;


    @Override
    public boolean verify(final Document document, final List<X509Certificate> certificates)
            throws MarshalException, XMLSignatureException {

        final NodeList nodeListSignature = document.getElementsByTagNameNS(XMLSignature.XMLNS,
                XAdESUtil.TAG_SIGNATURE);
        if (nodeListSignature.getLength() == 0) {
            return false;
        }

        final DOMValidateContext domValidateContext = new DOMValidateContext(new KeyValueKeySelector(),
                nodeListSignature.item(0));

        final XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
        final XMLSignature xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
        boolean valid = xmlSignature.validate(domValidateContext);

        List<Reference> references = xmlSignature.getSignedInfo().getReferences();
        references.forEach(r -> {
            try {
                System.out.printf("Reference id=%s, uri=%s, digestValue=%s%n", r.getId(), r.getURI(),
                        Arrays.toString(r.getDigestValue()));
                System.out.printf("Reference digestValueCalculated=%s%n",
                        Arrays.toString(r.getCalculatedDigestValue()));
                System.out.printf("Reference validation result: %s%n", r.validate(domValidateContext));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        checkAgainstStoredCertificates(currentPublicKey, certificates);
        return valid;
    }

    private void checkAgainstStoredCertificates(final PublicKey publicKey, final List<X509Certificate> certificates) {
        Defense.notNull(publicKey, "public key");
        final boolean certificateExist = certificates.stream().anyMatch(c -> c.getPublicKey().equals(publicKey));
        if (!certificateExist) {
            throw new IllegalArgumentException("Certificate does not exist in database.");
        }
    }

    @Override
    public boolean verify(final byte[] content, final List<X509Certificate> certificates) throws Exception {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        final Document document = documentBuilder.parse(new ByteArrayInputStream(content));
        return verify(document, certificates);
    }

    @Override
    public boolean verify(final String content, final List<X509Certificate> certificates) throws Exception {
        Defense.notNull(content, "content");
        return verify(content.getBytes(), certificates);
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private final PublicKey publicKey;

        public SimpleKeySelectorResult(final PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public Key getKey() {
            return publicKey;
        }
    }

    private class KeyValueKeySelector extends KeySelector {

        public KeySelectorResult select(final KeyInfo keyInfo, final KeySelector.Purpose purpose,
                final AlgorithmMethod method, final XMLCryptoContext context) throws KeySelectorException {
            Defense.notNull(keyInfo, "Key info");
            final List<?> keyInfoContent = keyInfo.getContent();

            PublicKey publicKey = findPublicKey(keyInfoContent);
            if (publicKey != null) {
                XAdESVerifier.this.currentPublicKey = publicKey;
                return new SimpleKeySelectorResult(publicKey);
            }

            throw new KeySelectorException("No PublicKey found");
        }

        private PublicKey findPublicKey(final List<?> keyInfoContent) {
            final AtomicReference<PublicKey> publicKey = new AtomicReference<>();
            keyInfoContent.forEach(keyInfoItem -> {
                if (keyInfoItem instanceof X509Data x509Data) {
                    publicKey.set(extractPublicKeyFromCertificate(x509Data));
                } else if (keyInfoItem instanceof KeyValue keyValue) {
                    publicKey.set(extractPublicKeyFromKeyValue(keyValue));
                }
            });
            return publicKey.get();
        }

        private PublicKey extractPublicKeyFromKeyValue(final KeyValue keyValue) {
            try {
                return keyValue.getPublicKey();
            } catch (KeyException ke) {
                throw new IllegalArgumentException(ke);
            }
        }

        private PublicKey extractPublicKeyFromCertificate(final X509Data x509Data) {
            final List<?> x509DataContent = x509Data.getContent();
            for (final Object x509Item : x509DataContent) {
                if (x509Item instanceof Certificate certificate) {
                    return certificate.getPublicKey();
                }
            }
            return null;
        }
    }
}
