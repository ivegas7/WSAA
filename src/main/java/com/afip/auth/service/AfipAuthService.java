package com.afip.auth.service;

import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Serializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.afip.auth.model.TokenResponse;
import com.afip.auth.util.LoginTicketRequestGenerator;
import com.afip.auth.util.XmlSigner;

import lombok.extern.slf4j.Slf4j;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.Map;

@Service
@Slf4j
public class AfipAuthService {

    private String token;

    @Value("${service}")
    private String service;

    private long expirationTime; 

    @Value("${endpoint}")
    private String endpoint;

    @Value("${keystore}")
    private String keystore;

    @Value("${keystore-signer}")
    private String keystore_signer;

    @Value("${keystore-password}")
    private String keystore_password;
    
    @Value("${config.time_expiration_token}")
    private long timeExpirationToken; 
    
    private DB db;
    private Map<String, Object> tokenMap;


    @PostConstruct
    public void init() {
        db = DBMaker.fileDB("tokenCache.db").make();
        tokenMap = db.hashMap("tokens", Serializer.STRING, Serializer.JAVA).createOrOpen();

        // Recuperamos el token persistido de MapDB
        if (tokenMap.containsKey("token")) {
            String savedToken = (String) tokenMap.get("token");
            Long savedExpirationTime = (Long) tokenMap.get("expirationTime");

            if (savedToken != null && savedExpirationTime != null && savedExpirationTime > System.currentTimeMillis()) {
                token = savedToken;
                expirationTime = savedExpirationTime;
                System.out.println("Token recuperado desde MapDB y es válido.");
            } else {
                System.out.println("Token expirado o no encontrado, generando nuevo token.");
            }
        } else {
            System.out.println("No se encontró token persistido, generando nuevo token.");
        }
    }

    public TokenResponse authenticate() {
        try {

            if (token == null || expirationTime < System.currentTimeMillis()) {
            	
                log.info("El token ha expirado o no existe. Generando un nuevo token.");
                
                // Generar el XML de solicitud de Ticket
                String loginRequestXml = LoginTicketRequestGenerator.generate(service, timeExpirationToken);
                log.info("LoginTicketRequest XML generado: " + loginRequestXml);
                
                // Firmar
                byte[] LoginTicketRequest_xml_cms = XmlSigner.createCMS(loginRequestXml, keystore, keystore_password, keystore_signer);
                log.info("LoginTicketRequest_xml_cms: " + LoginTicketRequest_xml_cms);
                
                // Invocar WSAA para obtener el token
                //token = "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\" standalone=\\\"yes\\\"?>\\n<loginTicketResponse version=\\\"1.0\\\">\\n    <header>\\n        <source>CN=wsaahomo, O=AFIP, C=AR, SERIALNUMBER=CUIT 33693450239</source>\\n        <destination>SERIALNUMBER=CUIT 20255676793, CN=sapqa</destination>\\n        <uniqueId>875041519</uniqueId>\\n        <generationTime>2025-03-18T01:15:18.838-03:00</generationTime>\\n        <expirationTime>2025-03-18T13:15:18.838-03:00</expirationTime>\\n    </header>\\n    <credentials>\\n        <token>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pgo8c3NvIHZlcnNpb249IjIuMCI+CiAgICA8aWQgc3JjPSJDTj13c2FhaG9tbywgTz1BRklQLCBDPUFSLCBTRVJJQUxOVU1CRVI9Q1VJVCAzMzY5MzQ1MDIzOSIgZHN0PSJDTj13c2ZlLCBPPUFGSVAsIEM9QVIiIHVuaXF1ZV9pZD0iMTQxNjUwMjU5NSIgZ2VuX3RpbWU9IjE3NDIyNzEyNTgiIGV4cF90aW1lPSIxNzQyMzE0NTE4Ii8+CiAgICA8b3BlcmF0aW9uIHR5cGU9ImxvZ2luIiB2YWx1ZT0iZ3JhbnRlZCI+CiAgICAgICAgPGxvZ2luIGVudGl0eT0iMzM2OTM0NTAyMzkiIHNlcnZpY2U9IndzZmUiIHVpZD0iU0VSSUFMTlVNQkVSPUNVSVQgMjAyNTU2NzY3OTMsIENOPXNhcHFhIiBhdXRobWV0aG9rPSJjbXMiIHJlZ21ldGhvZD0iMjIiPgogICAgICAgICAgICA8cmVsYXRpb25zPgogICAgICAgICAgICAgICAgPHJlbGF0aW9uIGtleT0iMzA2ODgzNTkxMjciIHJlbHR5cGU9IjQiLz4KICAgICAgICAgICAgPC9yZWxhdGlvbnM+CiAgICAgICAgPC9sb2dpbj4KICAgIDwvb3BlcmF0aW9uPgo8L3Nzbz4K</token>\\n        <sign>m4cIl9YumTsImMps2yyYZbjLNvI0CPtPkOgdkJjjTEpI2mViLSGpv7TkUUdbYef2Hg7Queudb8FhG21xHRj8obP+v1DEiYY0T3vVIcSwdIo6fWnZcnP/b1ZqKhE+ANmAX1QdEzmB7tAo0P0dN68tpqBSneEqUiTm0jTcAYhL6CY=</sign>\\n    </credentials>\\n</loginTicketResponse>\\n";
                token = XmlSigner.invoke_wsaa(LoginTicketRequest_xml_cms, endpoint);
                
                // Guardamos el nuevo token y la expiración en MapDB
                generateNewToken(token);
                log.info("Nuevo Token generado: " + token);
                
            } else {
                log.info("Token recuperado de caché: " + token);
            }

            return new TokenResponse(token);
        } catch (Exception e) {
            log.error("Error al generar o validar el token: " + e.getMessage());
            throw new RuntimeException("Error interno al generar o validar el token: " + e.getMessage());
        }
    }

    private void generateNewToken(String token) {
        try {
        	expirationTime = System.currentTimeMillis() +  (50* 1000); 
            //(timeExpirationToken * 60 * 60 * 1000)
        	//50 * 1000
            tokenMap.put("token", token);
            tokenMap.put("expirationTime", expirationTime);
            db.commit();

            log.info("Nuevo token generado y guardado en MapDB.");
            
        } catch (Exception e) {
            log.error("Error al generar el nuevo token: " + e.getMessage());
            throw new RuntimeException("Error interno al generar el nuevo token: " + e.getMessage());
        }
    }

    @PreDestroy
    public void shutdown() {
        if (db != null) {
            db.close();
        }
    }
}
