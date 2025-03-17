package com.afip.auth.util;

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

import com.afip.auth.errors.InternalErrorException;

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
    public static String invoke_wsaa(byte[] LoginTicketRequest_xml_cms, String endpoint) {
        String LoginTicketResponse = null;
        try {
            log.info("Iniciando invocación del servicio WSAA al endpoint: {}", endpoint);
            
            Service service = new Service();
            Call call = (Call) service.createCall();

            // Preparar la llamada al servicio web
            call.setTargetEndpointAddress(new URI(endpoint).toURL());
            call.setOperationName("loginCms");
            call.addParameter("request", XMLType.XSD_STRING, ParameterMode.IN);
            call.setReturnType(XMLType.XSD_STRING);      

            log.info("Codificando la solicitud en Base64...");
            String encodedRequest = Base64.getEncoder().encodeToString(LoginTicketRequest_xml_cms);

            // Invocar el servicio y obtener respuesta
            log.info("Realizando la invocación al servicio WSAA...");
            LoginTicketResponse = (String) call.invoke(new Object[]{encodedRequest});

            log.info("Respuesta obtenida del servicio WSAA.");
        } catch (Exception e) {
            log.error("Error al invocar el servicio WSAA: {}", e.getMessage());
            throw new InternalErrorException("Error al invocar el servicio WSAA: " + e.getMessage());
        }
        return LoginTicketResponse;
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
        byte[] asn1_cms = null;

        try {
            log.info("Cargando el archivo PKCS12 desde: {}", p12file);
            
            // Agregar el proveedor de seguridad BouncyCastle si no está presente
            if (Security.getProvider("BC") == null) {
                log.info("Añadiendo el proveedor BouncyCastle...");
                Security.addProvider(new BouncyCastleProvider());
            }

            // Cargar el almacén de claves (KeyStore) desde el archivo PKCS#12
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream p12stream = new FileInputStream(p12file)) {
                ks.load(p12stream, p12pass.toCharArray());
            }

            log.info("Clave privada y certificado obtenidos correctamente.");
            
            // Obtener clave privada y certificado
            pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
            pCertificate = (X509Certificate) ks.getCertificate(signer);

            
            // Convertir la clave privada a formato PEM (Base64)
//            String privateKeyString = getPrivateKeyString(pKey);
//            log.info("Clave privada en formato PEM:\n{}", privateKeyString); // Aquí se muestra la clave privada

            
            // Crear una lista de certificados
            List<X509Certificate> certList = Collections.singletonList(pCertificate);
            JcaCertStore certStore = new JcaCertStore(certList);

            // Construcción del generador de datos CMS
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC");

            log.info("Generando la firma CMS...");
            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(signerBuilder.build(pKey), pCertificate)
            );

            gen.addCertificates(certStore);
            
            
//          String LoginTicketRequest_xml_cms2 = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
//                  "xmlns:wsaa=\"http://wsaa.view.sua.dvadac.desein.afip.gov\">" +
//                  "<soapenv:Header/>" +
//                  "<soapenv:Body>" +
//                  "<wsaa:loginCms>" +
//                  "<wsaa:in0>" + privateKeyString + "</wsaa:in0>" +
//                  "</wsaa:loginCms>\n" +
//                  "</soapenv:Body>\n" +
//                  "</soapenv:Envelope>";
    

            // Añadir los datos XML a la firma
            CMSTypedData data = new CMSProcessableByteArray(loginRequestXml.getBytes());
            //CMSTypedData data2 = new CMSProcessableByteArray(LoginTicketRequest_xml_cms2.getBytes());
            
            CMSSignedData signedData = gen.generate(data, true);
            //signedData = gen.generate(data2, true);
            
            asn1_cms = signedData.getEncoded();

            log.info("CMS firmado generado correctamente.");
        } catch (Exception e) {
            log.error("Error al crear el CMS firmado: {}", e.getMessage());
            throw new InternalErrorException("Error al crear el CMS firmado: " + e.getMessage());
        }

        return asn1_cms;
    }
    
    public static String getPrivateKeyString(PrivateKey privateKey) {
        try {
            // Convertir la clave privada a un array de bytes
            byte[] privateKeyBytes = privateKey.getEncoded();

            // Codificar la clave privada en Base64
            String base64PrivateKey = Base64.getEncoder().encodeToString(privateKeyBytes);

            // Formatear como una clave privada en formato PEM
            StringBuilder pemPrivateKey = new StringBuilder();
//            pemPrivateKey.append("-----BEGIN PRIVATE KEY-----\n");
            pemPrivateKey.append(base64PrivateKey);
//            pemPrivateKey.append("\n-----END PRIVATE KEY-----");

            return pemPrivateKey.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
