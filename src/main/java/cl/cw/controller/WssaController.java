package cl.cw.controller;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Controller for handling AFIP authentication requests.
 */

import cl.cw.service.WssaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import cl.cw.model.TokenResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class WssaController {

    private final WssaService WssaService;

    @GetMapping("/api/arca/wssa")
    public ResponseEntity<TokenResponse> authenticate() {
        log.info("Obtaining token");
        TokenResponse tokenResponse = WssaService.authenticate();
        return ResponseEntity.ok(tokenResponse);
    }
}
