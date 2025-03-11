package com.afip.auth.util;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.net.URI;
import javax.xml.rpc.ParameterMode;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.encoding.XMLType;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class XmlSigner {

    /**
     * Invoca el servicio WSAA enviando la solicitud de autenticación.
     * @param loginTicketRequestXmlCms XML firmado en formato CMS
     * @param endpoint URL del servicio WSAA
     * @return Respuesta del WSAA en formato String
     * @throws Exception En caso de error al invocar el servicio
     */
    public static String invokeWSAA(byte[] loginTicketRequestXmlCms, String endpoint) throws Exception {
        String loginTicketResponse = null;
        try {
            Service service = new Service();
            Call call = (Call) service.createCall();
            
            // Convierte el XML CMS en Base64
            String base64Cms = Base64.getEncoder().encodeToString(loginTicketRequestXmlCms);
            base64Cms = base64Cms.replace("\n", "").replace("\r", "");
            String soapRequest = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                    "xmlns:wsaa=\"http://wsaa.view.sua.dvadac.desein.afip.gov\">\n" +
                    "   <soapenv:Header/>\n" +
                    "   <soapenv:Body>\n" +
                    "      <wsaa:loginCms>\n" +
                    "         <wsaa:in0>" + base64Cms + "</wsaa:in0>\n" +
                    "      </wsaa:loginCms>\n" +
                    "   </soapenv:Body>\n" +
                    "</soapenv:Envelope>";
            
            log.info("SOAP Request: {}", soapRequest);
            log.info("Base64 CMS: {}", base64Cms);
            
            // Configura el endpoint y el nombre de la operación SOAP
            call.setTargetEndpointAddress(new URI(endpoint).toURL());
            call.setOperationName("loginCms");
            
            call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
            call.setReturnType(XMLType.XSD_STRING);
            
            // Invoca el servicio SOAP y recibe la respuesta
            loginTicketResponse = (String) call.invoke(new Object[]{soapRequest});
            
        } catch (Exception e) {
            log.error("Error invoking WSAA with endpoint: {}", endpoint, e);
            throw new Exception("Error invoking WSAA", e);
        }
        return loginTicketResponse;
    }

    /**
     * Crea un CMS firmado a partir del XML de autenticación.
     * @param loginRequestXml Contenido del XML de solicitud de autenticación
     * @param p12file Ruta al archivo PKCS12 (.p12)
     * @param p12pass Contraseña del archivo PKCS12
     * @param signer Alias del firmante dentro del almacén de claves
     * @return CMS firmado en bytes
     */
    public static byte[] createCMS(String loginRequestXml, String p12file, String p12pass, String signer) {
        PrivateKey pKey = null;
        X509Certificate pCertificate = null;
        byte[] asn1Cms = null;
        
        try (FileInputStream p12stream = new FileInputStream(p12file)) {
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(p12stream, p12pass.toCharArray());
            
            // Verifica si el alias del firmante existe en el almacén de claves
            if (!ks.containsAlias(signer)) {
                throw new RuntimeException("Signer alias not found in KeyStore");
            }
            
            // Obtiene la clave privada y el certificado asociado al firmante
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate) ks.getCertificate(signer);
            
            // Agrega BouncyCastle como proveedor de seguridad si no está registrado
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (Exception e) {
            log.error("Error loading key store: {}", p12file, e);
            throw new RuntimeException("Error loading key store", e);
        }
        
        try {
            // Crea generador de datos firmados CMS
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().build())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(pKey), pCertificate));
            
            // Agrega la lista de certificados al generador
            List<X509Certificate> certList = new ArrayList<>();
            certList.add(pCertificate);
            gen.addCertificates(new JcaCertStore(certList));
            
            // Convierte el XML a un objeto CMS y lo firma
            CMSTypedData data = new org.bouncycastle.cms.CMSProcessableByteArray(loginRequestXml.getBytes());
            CMSSignedData signed = gen.generate(data, true);
            asn1Cms = signed.getEncoded();
            
            log.info("Certificate: {}", pCertificate);
            log.info("Private Key: {}", pKey);
            
        } catch (Exception e) {
            log.error("Error creating CMS signature", e);
            throw new RuntimeException("Error creating CMS signature", e);
        }
        
        return asn1Cms;
    }
}
