package dev.beenary.xades;

import org.w3c.dom.Document;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

public interface Verifier {

    boolean verify(Document document, List<X509Certificate> certificates)
            throws MarshalException, XMLSignatureException;

    boolean verify(byte[] signed, final List<X509Certificate> certificates) throws Exception;

    boolean verify(String signed, final List<X509Certificate> certificates) throws Exception;

}
