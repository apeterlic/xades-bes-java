package dev.beenary.xades;

import org.w3c.dom.Document;

/**
 *
 */
public interface Signer {
    Document sign(final String content) throws Exception;

    Document sign(final byte[] content) throws Exception;
}
