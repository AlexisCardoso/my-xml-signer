package com.faturafacil;

import org.w3c.dom.Document;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.*;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Signer {

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: java -jar xml-signer.jar <unsigned_xml_path> <signed_xml_path> <pkcs12_path> <pkcs12_password>");
            System.exit(1);
        }

        String unsignedXmlPath = args[0];
        String signedXmlPath = args[1];
        String pkcs12Path = args[2];
        String pkcs12Password = args[3];

        try {
            // Use a PKCS12 file which contains both the private key and the certificate chain.
            // You can create a PKCS12 (.p12/.pfx) file from your .crt and .key files using OpenSSL:
            // openssl pkcs12 -export -out efatura_cert.p12 -inkey efatura_private_v2_rsa.key -in efatura_cert_v2.crt
            KeyingDataProvider keyingDataProvider = new FileSystemKeyStoreKeyingDataProvider(
                    "pkcs12",
                    pkcs12Path,
                    (certificateSelector) -> new DirectPasswordProvider(pkcs12Password),
                    (entryAlias, privateKey, chain) -> new DirectPasswordProvider(pkcs12Password),
                    (entryAlias, privateKey, chain) -> true // Select the first available key/cert
            );

            // Create a XAdES-BES signer
            XadesBesSigningProfile profile = new XadesBesSigningProfile(keyingDataProvider);
            XadesSigner signer = profile.newSigner();

            // Read the XML to be signed
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new FileInputStream(unsignedXmlPath));

            // Define the data object to be signed
            DataObjectDesc obj = new DataObjectReference("")
                    .withTransform(new EnvelopedSignatureTransform());

            // Sign the document
            signer.sign(obj, doc.getDocumentElement());

            // Write the signed XML to the output file
            try (FileOutputStream fos = new FileOutputStream(signedXmlPath)) {
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer t = tf.newTransformer();
                t.transform(new DOMSource(doc), new StreamResult(fos));
            }

            System.out.println("XML signed successfully! Output: " + signedXmlPath);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
