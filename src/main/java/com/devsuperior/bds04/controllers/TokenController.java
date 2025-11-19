package com.devsuperior.bds04.controllers;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/oauth2")
public class TokenController {

	private static final MediaType JSON_UTF8 = MediaType.valueOf("application/json;charset=UTF-8");

	private final AuthenticationManager authenticationManager;
	private final JwtEncoder jwtEncoder;
	private final String clientId;
	private final String clientSecret;
	private final long jwtDuration;

	public TokenController(AuthenticationManager authenticationManager, JwtEncoder jwtEncoder,
			@Value("${security.client-id}") String clientId,
			@Value("${security.client-secret}") String clientSecret,
			@Value("${jwt.duration}") long jwtDuration) {
		this.authenticationManager = authenticationManager;
		this.jwtEncoder = jwtEncoder;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.jwtDuration = jwtDuration;
	}

	@PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = "application/json;charset=UTF-8")
	public ResponseEntity<Map<String, Object>> token(
			@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
			@RequestParam MultiValueMap<String, String> params) {

		validateClient(authorization);
		validateGrantType(params.getFirst("grant_type"));

		String username = params.getFirst("username");
		String password = params.getFirst("password");

		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credenciais inválidas");
		}

		Authentication authentication = authenticationManager
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, password));

		String authorities = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.map(auth -> auth.replace("ROLE_", ""))
				.collect(Collectors.joining(" "));

		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject(authentication.getName())
				.issuedAt(now)
				.expiresAt(now.plusSeconds(jwtDuration))
				.claim("authorities", authorities)
				.build();

		JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();
		JwtEncoderParameters parameters = JwtEncoderParameters.from(jwsHeader, claims);
		String tokenValue = jwtEncoder.encode(parameters).getTokenValue();

		Map<String, Object> body = new HashMap<>();
		body.put("access_token", tokenValue);
		body.put("token_type", "Bearer");
		body.put("expires_in", jwtDuration);

		return ResponseEntity.ok()
				.contentType(JSON_UTF8)
				.body(body);
	}

	private void validateClient(String authorization) {
		if (!StringUtils.hasText(authorization) || !authorization.startsWith("Basic ")) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Cliente inválido");
		}
		byte[] decoded = Base64.getDecoder().decode(authorization.substring(6));
		String credentials = new String(decoded, StandardCharsets.UTF_8);
		String[] values = credentials.split(":", 2);
		if (values.length != 2 || !clientId.equals(values[0]) || !clientSecret.equals(values[1])) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Cliente inválido");
		}
	}

	private void validateGrantType(String grantType) {
		if (!"password".equals(grantType)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Grant type inválido");
		}
	}
}

