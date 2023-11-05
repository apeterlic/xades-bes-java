package dev.beenary;

import dev.beenary.xades.Signer;
import dev.beenary.xades.XAdESSigner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

/**
 * Application for signing XML documents with XAdES.
 *
 * @author Ana Peterlić
 */
public class Application {

    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        org.apache.xml.security.Init.init();
    }

    public static void main(final String[] args) throws Exception {
        final Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the path to the certificate (.csr, .cer):");
        //final String certificateFile = scanner.nextLine();
        final String certificateFile = "/Users/anapeterlic/Downloads/xades-bes-master/src/main/resources/certificate" +
                ".cer";


        System.out.println("Enter the path to the private key file (.pem):");
       // final String privateKeyFile = scanner.nextLine();
        final String privateKeyFile = "/Users/anapeterlic/Downloads/xades-bes-master/src/main/resources/privatekey.pem";

        System.out.println("Enter the password for private key:");
        final String privateKeyPass = scanner.nextLine();

        System.out.println("Enter the path to the XML you want to sign:");
      //  final String xmlPath = scanner.nextLine();
        final String xmlPath = "/Users/anapeterlic/Downloads/xades-bes-master/src/test/resources/xades/unsigned1.xml";
        final byte[] encoded = Files.readAllBytes(Path.of(xmlPath));

        final Signer xAdESSigner = new XAdESSigner(certificateFile, privateKeyFile, privateKeyPass);
        xAdESSigner.sign(encoded);
    }
}
