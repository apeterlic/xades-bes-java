package dev.beenary.xades;

import dev.beenary.exception.XAdESVerifyException;
import dev.beenary.util.Defense;
import dev.beenary.util.XAdESUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
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
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static dev.beenary.util.XAdESUtil.ATTRIBUTE_ID;

/**
 * Represents class for signing XML documents using XAdES format.
 *
 * @author Ana Peterlić
 */
public class XAdESSigner implements Signer {

    public static final String TAG_SIGNED_PROPERTIES = "SignedProperties";
    public static final String TAG_SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";
    public static final String TAG_SIGNING_TIME = "SigningTime";
    public static final String CERTIFICATE_TYPE_X_509 = "X509";
    private String certificateFilePath;
    private String privateKeyFilePath;
    protected String privateKeyPassword;

    protected PrivateKey privateKey;
    protected X509Certificate certificate;

    public XAdESSigner(final String certificateFilePath, final String privateKeyPath, final String privateKeyPassword) {
        this.certificateFilePath = certificateFilePath;
        this.privateKeyFilePath = privateKeyPath;
        this.privateKeyPassword = privateKeyPassword;
    }

    public XAdESSigner(final X509Certificate certificate, final PrivateKey privateKey) {
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
        final XMLSignature xmlSignature = createXMLSignature(document);
        final Element rootNode = document.getDocumentElement();
        final DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);
        xmlSignature.sign(domSignContext);
        documentToString(document);
        return document;
    }

    private void documentToString(final Document document) throws TransformerException {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            //transformer.setOutputProperty(OutputKeys.STANDALONE, "no");
            DOMSource source = new DOMSource(document);
            FileWriter writer = new FileWriter("text.xml");
            StreamResult result = new StreamResult(writer);
            transformer.transform(source, result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        final DOMSource domSource = new DOMSource(document);
        final StringWriter writer = new StringWriter();
        final StreamResult result = new StreamResult(writer);
        final TransformerFactory transformerFactory = TransformerFactory.newInstance();
        final Transformer transformer = transformerFactory.newTransformer();
        transformer.transform(domSource, result);
        //transformer.setOutputProperty(OutputKeys.STANDALONE, "no");

        String res = writer.toString();
        res = res.replaceAll("\\n", "");
        res = res.replaceAll("\\r", "");
        System.out.println("Signed XML IN String format is: \n" + writer);
    }

    protected XMLSignature createXMLSignature(final Document document) throws Exception {
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
        final Reference referenceDoc = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);
       // final Reference referenceQuP = xmlSignatureFactory.newReference("#DPI_OECD" ,
        //        xmlSignatureFactory.newDigestMethod(XAdESUtil.DIGEST_ALGORITHM, null));

        final List<Reference> references = List.of(referenceDoc);
        final SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);

        final KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        final X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
        final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

        //final Element qualifyingPropertiesElement = buildQualifyingProperties(document,
        //        XAdESUtil.QUALIFYING_PROPERTIES_ID);
        //final DOMStructure qualifyingPropertiesObject = new DOMStructure(qualifyingPropertiesElement);
        //final XMLObject qualifyingPropertiesXMLObject = xmlSignatureFactory.newXMLObject(
         //       Collections.singletonList(qualifyingPropertiesObject), null, null, null);

        //final List<XMLObject> objects = List.of(qualifyingPropertiesXMLObject);
        return xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, "xmldsig-" + UUID.randomUUID(), null);
    }

    protected Element buildQualifyingProperties(final Document document, final String id) {

        final Element qualifyingPropertiesElement = document.createElement(null);
        if (id != null && !id.isEmpty()) {
            qualifyingPropertiesElement.setAttribute(ATTRIBUTE_ID, id);
            qualifyingPropertiesElement.setIdAttribute(ATTRIBUTE_ID, true);
        }

        final Element signedPropertiesElement = document.createElement(TAG_SIGNED_PROPERTIES);
        qualifyingPropertiesElement.appendChild(signedPropertiesElement);

        final Element signedSignaturePropertiesElement = document.createElement(TAG_SIGNED_SIGNATURE_PROPERTIES);
        signedPropertiesElement.appendChild(signedSignaturePropertiesElement);

        final String signingTime = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(LocalDateTime.now());
        final Element signingTimeElement = document.createElement(TAG_SIGNING_TIME);
        signingTimeElement.setTextContent(signingTime);
        signedSignaturePropertiesElement.appendChild(signingTimeElement);

        return qualifyingPropertiesElement;
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

    protected PrivateKey loadPrivateKeyFile() {
        Defense.notNull(privateKeyFilePath, "Private key file path");
        final FileInputStream fileInputStream = pathToFileInputStream(privateKeyFilePath);

        try (final PEMParser pemParser = new PEMParser(new InputStreamReader(fileInputStream))) {
            Security.addProvider(new BouncyCastleProvider());
            final Object object = pemParser.readObject();

            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(privateKeyPassword.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair pemEncryptedKeyPair) {
                System.out.println("Encrypted key - we will use provided password");
                kp = converter.getKeyPair(pemEncryptedKeyPair.decryptKeyPair(decProv));
            } else {
                System.out.println("Unencrypted key - no password needed");
                kp = converter.getKeyPair((PEMKeyPair) object);
            }

            return kp.getPrivate();

        } catch (Exception e) {
            throw new XAdESVerifyException("Invalid pem file " + privateKeyFilePath);
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

