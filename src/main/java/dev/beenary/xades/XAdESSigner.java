package dev.beenary.xades;

import dev.beenary.exception.XAdESVerifyException;
import dev.beenary.util.Defense;
import dev.beenary.util.XAdESUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Represents class for signing XML documents using XAdES format.
 *
 * @author Ana Peterlić
 */
public class XAdESSigner implements Signer {

    public static final String CERTIFICATE_TYPE_X_509 = "X509";
    private String certificateFilePath;
    private String privateKeyFilePath;
    protected String privateKeyPassword;

    protected ECPrivateKey privateKey;
    protected X509Certificate certificate;

    public XAdESSigner(final String certificateFilePath, final String privateKeyPath, final String privateKeyPassword) {
        this.certificateFilePath = certificateFilePath;
        this.privateKeyFilePath = privateKeyPath;
        this.privateKeyPassword = privateKeyPassword;
    }

    public XAdESSigner(final X509Certificate certificate, final ECPrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public Document sign(String content) throws Exception {
        Defense.notNull(content, "content");
        return sign(content.getBytes());
    }

    @Override
    public Document sign(byte[] content) throws Exception {
        Defense.notNull(content, "content");
        if (this.privateKey == null) {
            this.privateKey = loadPrivateKeyFile();
            Defense.notNull(privateKey, "private key");
        }

        if (this.certificate == null) {
            this.certificate = loadCertificateFile();
            Defense.notNull(this.certificate, "certificate");
        }

        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        final Document document = documentBuilder.parse(new ByteArrayInputStream(content));
        final XMLSignature xmlSignature = createXMLSignature();
        final Element rootNode = document.getDocumentElement();
        rootNode.setIdAttribute("Id", true);
        final DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);
        xmlSignature.sign(domSignContext);
        documentToString(document);
        return document;
    }

    private void documentToString(final Document document) throws TransformerException {
        final DOMSource domSource = new DOMSource(document);
        final StringWriter writer = new StringWriter();
        final StreamResult result = new StreamResult(writer);
        final TransformerFactory transformerFactory = TransformerFactory.newInstance();
        final Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(domSource, result);
        System.out.println("Signed XML IN String format is: \n" + writer);
    }

    protected XMLSignature createXMLSignature() throws Exception {
        final XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM",
                new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        final CanonicalizationMethod c14nMethod =
                xmlSignatureFactory.newCanonicalizationMethod(XAdESUtil.CANONICALIZATION_ALGORITHM,
                        (C14NMethodParameterSpec) null);
        final DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(XAdESUtil.DIGEST_ALGORITHM, null);
        final SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod(XAdESUtil.SIGN_ALGORITHM, null);
        final Transform sigTransform = xmlSignatureFactory.newTransform(XAdESUtil.TRANSFORM_ALGORITHM,
                (TransformParameterSpec) null);
        final Transform canTransform = xmlSignatureFactory.newTransform(XAdESUtil.CANONICALIZATION_ALGORITHM,
                (TransformParameterSpec) null);

        final List<Transform> transforms = List.of(sigTransform, canTransform);
        final Reference referenceDoc = xmlSignatureFactory.newReference("#DPIOECD", digestMethod, transforms, null,
                null);
        final List<Reference> references = List.of(referenceDoc);
        final SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);
        final KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        final X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
        return xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, "xmldsig-" + UUID.randomUUID(), null);
    }

    X509Certificate loadCertificateFile() {
        Defense.notNull(certificateFilePath, "Provided certificate path is invalid.");

        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE_X_509);
            final FileInputStream fileInputStream = pathToFileInputStream(certificateFilePath);
            final X509Certificate x509Certificate =
                    (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            System.out.println("Certificate found!");
            return x509Certificate;
        } catch (Exception e) {
            throw new XAdESVerifyException("Error tying to read certificate from a given path.");
        }
    }

    protected ECPrivateKey loadPrivateKeyFile() {
        Defense.notNull(privateKeyFilePath, "Private key file path");

        try {
            final FileInputStream fis = new FileInputStream(privateKeyFilePath);
            final BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            final KeyStore keyStore = KeyStore.getInstance("pkcs12", "SunJSSE");
            keyStore.load(fis, privateKeyPassword.toCharArray());
            final String alias = keyStore.aliases().nextElement();
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword.toCharArray());
            final Certificate[] chain = keyStore.getCertificateChain(alias);
            final X509Certificate last = (X509Certificate) chain[chain.length - 1];
            System.out.printf("Valid from %s until %s %n", last.getNotAfter(), last.getNotBefore());
            return (ECPrivateKey) privateKey;
        } catch (Exception e) {
            System.err.println(e);
            throw new XAdESVerifyException("Invalid private key file " + privateKeyFilePath);
        }
    }

    private FileInputStream pathToFileInputStream(final String name) {
        try {
            return new FileInputStream(name);
        } catch (FileNotFoundException e) {
            throw new XAdESVerifyException("Could not read from given file path.");
        }
    }

}

