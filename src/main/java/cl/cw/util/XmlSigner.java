package cl.cw.util;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Utility class for creating and invoking signed XML requests to the WSAA service.
 */

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Base64;
import java.util.Collections;
import java.net.URI;
import javax.xml.rpc.ParameterMode;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.XMLType;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import cl.cw.errors.InternalErrorException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class XmlSigner {

	/**
	* Invokes the WSAA service by sending the authentication request.
	* @param LoginTicketRequest_xml_cms Signed XML in CMS format
	* @param endpoint WSAA service URL
	* @return WSAA response in String format
	* @throws Exception If an error occurs while invoking the service
	*/

    public static String invoke_wsaa(byte[] LoginTicketRequest_xml_cms, String endpoint) {
        String LoginTicketResponse = null;
        try {
            log.info("Starting WSAA service invocation to endpoint: {}", endpoint);
            
            Service service = new Service();
            Call call = (Call) service.createCall();

            // Prepare the call to the web service
            call.setTargetEndpointAddress(new URI(endpoint).toURL());
            call.setOperationName("loginCms");
            call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
            call.setReturnType(XMLType.XSD_STRING);      

            log.info("Base64 encoding the request...");
            String encodedRequest = Base64.getEncoder().encodeToString(LoginTicketRequest_xml_cms);

            // Invoke the service and get a response
            log.info("Performing WSAA service invocation...");
            LoginTicketResponse = (String) call.invoke(new Object[]{encodedRequest});

            log.info("Response obtained from the WSAA service.");
        } catch (Exception e) {
            log.error("Error invoking WSAA service: {}", e.getMessage());
            throw new InternalErrorException("Error invoking WSAA service: " + e.getMessage());
        }
        return LoginTicketResponse;
    }

    /**
    * Creates a signed CMS from the authentication XML.
    * @param loginRequestXml Contents of the authentication request XML
    * @param p12file Path to the PKCS12 file (.p12)
    * @param p12pass Password for the PKCS12 file
    * @param signer Alias ​​of the signer within the keystore
    * @return CMS signed in bytes
    */
    public static byte[] createCMS(String loginRequestXml, String p12file, String p12pass, String signer) {
        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1_cms = null;

        try {
            log.info("Loading PKCS12 file from: {}", p12file);
            
            // Add the BouncyCastle security provider if not present
            if (Security.getProvider("BC") == null) {
                log.info("Adding the BouncyCastle provider...");
                Security.addProvider(new BouncyCastleProvider());
            }

            // Load the key store (KeyStore) from the PKCS#12 file
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream p12stream = new FileInputStream(p12file)) {
                ks.load(p12stream, p12pass.toCharArray());
            }

            log.info("Private key and certificate obtained successfully.");
            
            // Obtain private key and certificate
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate) ks.getCertificate(signer);      
            
            // Create a list of certificates
            List<X509Certificate> certList = Collections.singletonList(pCertificate);
            JcaCertStore certStore = new JcaCertStore(certList);

            // Construction of the CMS data generator
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

            log.info("Generating the CMS signature...");
            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(signerBuilder.build(pKey), pCertificate)
            );

            gen.addCertificates(certStore);
            
            // Add the XML data to the signature
            CMSTypedData data = new CMSProcessableByteArray(loginRequestXml.getBytes());
            
            CMSSignedData signedData = gen.generate(data, true);
           
            asn1_cms = signedData.getEncoded();

            log.info("Signed CMS generated successfully.");
        } catch (Exception e) {
            log.error("Error creating the signed CMS: {}", e.getMessage());
            throw new InternalErrorException("Error creating the signed CMS: " + e.getMessage());
        }

        return asn1_cms;
    }
    
}
