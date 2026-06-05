package com.maruf.auth.controller;

import com.maruf.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class WellKnownController {

	private final JwtService jwtService;

	@GetMapping("/.well-known/jwks.json")
	public Map<String, Object> jwks() {
		RSAPublicKey publicKey = jwtService.getPublicKey();

		byte[] modulusBytes = publicKey.getModulus().toByteArray();
		if (modulusBytes[0] == 0) {
			byte[] tmp = new byte[modulusBytes.length - 1];
			System.arraycopy(modulusBytes, 1, tmp, 0, tmp.length);
			modulusBytes = tmp;
		}

		byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();
		if (exponentBytes[0] == 0) {
			byte[] tmp = new byte[exponentBytes.length - 1];
			System.arraycopy(exponentBytes, 1, tmp, 0, tmp.length);
			exponentBytes = tmp;
		}

		String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulusBytes);
		String e = Base64.getUrlEncoder().withoutPadding().encodeToString(exponentBytes);

		Map<String, Object> key = Map.of(
				"kty", "RSA",
				"use", "sig",
				"alg", "RS256",
				"kid", "1",
				"n", n,
				"e", e);

		return Map.of("keys", List.of(key));
	}
}
