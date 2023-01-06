package com.oauth2.login.global.security.auth.jwt;

import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {

	/*
	 * 유저 정보로 JWT 토큰을 만들거나 토큰을 바탕으로 유저 정보를 가져옴
	 *  JWT 토큰 관련 암호화, 복호화, 검증 로직
	 */
	private static final String BEARER_TYPE = "bearer";

	@Value("${jwt.access-token-expiration-minutes}")
	private int accessTokenExpirationMinutes;

	@Value("${jwt.refresh-token-expiration-minutes}")
	private int refreshTokenExpirationMinutes;

	private final Key key;

	public TokenProvider(@Value("${jwt.secret-key}") String secretKey) {
		byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
		this.key = Keys.hmacShaKeyFor(keyBytes);
	}

	public Date getTokenExpiration(int expirationMinutes) {
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, expirationMinutes);
		return calendar.getTime();
	}

	public TokenDto generateTokenDto(AuthMember authMember) {
		// 권한들 가져오기
		String authorities = authMember.getAuthorities().stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.joining(","));

		Date accessTokenExpiresIn = getTokenExpiration(accessTokenExpirationMinutes);
		Date refreshTokenExpiresIn = getTokenExpiration(refreshTokenExpirationMinutes);

		Map<String, Object> claims = new HashMap<>();
		claims.put("id", authMember.getId());
		claims.put("roles", authMember.getAuthorities());

		// Access Token 생성
		String accessToken = Jwts.builder()
			.setSubject(authMember.getEmail())                  // payload "sub": "email"
			.setClaims(claims)      							// payload "auth": "ROLE_USER"
			.setExpiration(accessTokenExpiresIn)                // payload "exp": 1516239022 (예시)
			.signWith(key, SignatureAlgorithm.HS512)         	// header "alg": "HS512"
			.compact();

		// Refresh Token 생성
		String refreshToken = Jwts.builder()
			.setSubject(authMember.getEmail().toString())
			.setExpiration(refreshTokenExpiresIn)
			.signWith(key, SignatureAlgorithm.HS512)
			.compact();

		return TokenDto.builder()
			.grantType(BEARER_TYPE)
			.accessToken(accessToken)
			.accessTokenExpiresIn(accessTokenExpiresIn.getTime())
			.refreshToken(refreshToken)
			.build();
	}

	public Authentication getAuthentication(String accessToken) {
		// 토큰 복호화
		Claims claims = parseClaims(accessToken);

		if (claims.get("roles") == null) {
			throw new RuntimeException("권한 정보가 없는 토큰입니다.");
		}

		// 클레임에서 권한 정보 가져오기
		List<String> authorities = Arrays.stream(claims.get("roles").toString().split(","))
			.collect(Collectors.toList());

		AuthMember auth = AuthMember.of(claims.get("id", Long.class), authorities);
		return new UsernamePasswordAuthenticationToken(auth, auth.getPassword(), auth.getAuthorities());
	}

	// 토큰 검증
	public boolean validateToken(String token) {

		try {
			parseClaims(token);
			return true;
		} catch (SignatureException e) {
			log.info("Invalid JWT signature");
			log.trace("Invalid JWT signature trace: {}", e);
			// throw new TokenSignatureInvalid(); // 예외처리 커스텀를 위한 로직
			throw new RuntimeException("Token Signature Invalid");
		} catch (MalformedJwtException e) {
			log.info("Invalid JWT token");
			log.trace("Invalid JWT token trace: {}", e);
			// throw new TokenMalformed();
			throw new RuntimeException("Token Malformed");
		} catch (ExpiredJwtException e) {
			log.info("Expired JWT token");
			log.trace("Expired JWT token trace: {}", e);
			// throw new TokenExpired();
			throw new RuntimeException("Token Expired");
		} catch (UnsupportedJwtException e) {
			log.info("Unsupported JWT token");
			log.trace("Unsupported JWT token trace: {}", e);
			// throw new TokenUnsupported();
			throw new RuntimeException("Token Unsupported");
		} catch (IllegalArgumentException e) {
			log.info("JWT claims string is empty.");
			log.trace("JWT claims string is empty trace: {}", e);
			// throw new TokenEmpty();
			throw new RuntimeException("TToken Illegal Argument");
		}

	}

	public Claims parseClaims(String accessToken)  {

		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(accessToken)
				.getBody();
	}

}
