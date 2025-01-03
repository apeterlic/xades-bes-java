package dev.beenary.util;

/**
 * Represents class that contains common algorithm constants.
 *
 * @author Ana Peterlić
 */
public final class XAdESUtil {

    public static final String TRANSFORM_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    public static final String CANONICALIZATION_ALGORITHM = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public static final String DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String SIGN_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String ATTRIBUTE_ID = "Id";
    public static final String TAG_SIGNATURE = "Signature";

    /**
     * Class contains only static memebers and should never be instantiated.
     */
    private XAdESUtil() {
    }
}
