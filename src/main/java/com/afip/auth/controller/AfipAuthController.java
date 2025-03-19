package com.afip.auth.controller;

/**
 * Company: [CrossWave SPA]
 * Project: AFIP Authentication System
 * Author: [Ignacio Vegas Fernández]
 * Description: Controller for handling AFIP authentication requests.
 */

import com.afip.auth.service.AfipAuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.afip.auth.model.TokenResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AfipAuthController {

    private final AfipAuthService afipAuthService;

    @GetMapping("/auth/afip/authenticate")
    public ResponseEntity<TokenResponse> authenticate() {
        log.info("Obtaining token");
        TokenResponse tokenResponse = afipAuthService.authenticate();
        return ResponseEntity.ok(tokenResponse);
    }
}
