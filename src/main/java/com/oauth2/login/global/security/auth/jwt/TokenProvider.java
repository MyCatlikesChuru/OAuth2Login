package com.oauth2.login.global.security.auth.jwt;

import com.oauth2.login.global.common.redis.RedisDao;
import com.oauth2.login.global.exception.BusinessLogicException;
import com.oauth2.login.global.exception.ExceptionCode;
import com.oauth2.login.global.security.auth.dto.TokenDto;
import com.oauth2.login.global.security.auth.userdetails.AuthMember;
import com.oauth2.login.global.security.auth.utils.Responder;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenProvider {

	/*
	 * 유저 정보로 JWT 토큰을 만들거나 토큰을 바탕으로 유저 정보를 가져옴
	 * JWT 토큰 관련 암호화, 복호화, 검증 로직
	 */
	public static final String BEARER_TYPE = "Bearer";
	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String BEARER_PREFIX = "Bearer ";

	@Getter
	@Value("${jwt.secret-key}")
	private String secretKey;

	@Getter
	@Value("${jwt.access-token-expiration-minutes}")
	private int accessTokenExpirationMinutes;

	@Getter
	@Value("${jwt.refresh-token-expiration-minutes}")
	private int refreshTokenExpirationMinutes;

	private Key key;

	// Bean 등록후 Key SecretKey HS256 decode
	@PostConstruct
	public void init(){
		String encode = Encoders.BASE64.encode(this.secretKey.getBytes(StandardCharsets.UTF_8));
		byte[] keyBytes = Decoders.BASE64.decode(encode);
		this.key = Keys.hmacShaKeyFor(keyBytes);
	}

	public Date getTokenExpiration(int expirationMinutes) {
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MINUTE, expirationMinutes);
		return calendar.getTime();
	}

	public TokenDto generateTokenDto(AuthMember authMember) {

		Date accessTokenExpiresIn = getTokenExpiration(accessTokenExpirationMinutes);
		Date refreshTokenExpiresIn = getTokenExpiration(refreshTokenExpirationMinutes);

		Map<String, Object> claims = new HashMap<>();
		claims.put("roles", authMember.getRoles());
		claims.put("id", authMember.getId());

		// Access Token 생성
		String accessToken = Jwts.builder()
			.setClaims(claims)      							// payload "roles": "USER"
			.setSubject(authMember.getEmail())                  // payload "sub": "email@naver.com"
			.setIssuedAt(Calendar.getInstance().getTime())		// payload "iat" : 1673108836
			.setExpiration(accessTokenExpiresIn)                // payload "exp": 1673110636
			.signWith(key, SignatureAlgorithm.HS256)         	// header "alg": "HS512"
			.compact();

		// Refresh Token 생성
		String refreshToken = Jwts.builder()
			.setSubject(authMember.getEmail())
			.setIssuedAt(Calendar.getInstance().getTime())
			.setExpiration(refreshTokenExpiresIn)
			.signWith(key, SignatureAlgorithm.HS256)
			.compact();

		return TokenDto.builder()
			.grantType(BEARER_TYPE)
			.authorizationType(AUTHORIZATION_HEADER)
			.accessToken(accessToken)
			.accessTokenExpiresIn(accessTokenExpiresIn.getTime())
			.refreshToken(refreshToken)
			.build();
	}

	public Authentication getAuthentication(String accessToken) {
		// 토큰 복호화
		Claims claims = parseClaims(accessToken);

		if (claims.get("roles") == null) {
			throw new BusinessLogicException(ExceptionCode.NO_ACCESS_TOKEN);
		}

		// 클레임에서 권한 정보 가져오기
		List<String> authorities = Arrays.stream(
				claims.get("roles")
						.toString()
						.replace("[","")
						.replace("]","")
						.replace(" ","")
						.split(","))
			.collect(Collectors.toList());

		AuthMember auth = AuthMember.of(
				claims.get("id", Long.class),
				claims.get("sub", String.class),
				authorities);

		auth.getRoles().stream().forEach(authMember -> log.info("# AuthMember.getRoles 권한 체크 = {}", authMember));
		// auth.getAuthorities().stream().forEach(a -> log.info("# auth.getAuthorities 권한 체크 = {}",a));

		return new UsernamePasswordAuthenticationToken(auth, null, auth.getAuthorities());
	}



	// 토큰 검증
	public boolean validateToken(String token, HttpServletResponse response) {

		try {
			parseClaims(token);
		} catch (SignatureException e) {
			log.info("Invalid JWT signature");
			log.trace("Invalid JWT signature trace = {}", e);
			Responder.sendErrorResponse(response, ExceptionCode.TOKEN_SIGNATURE_INVALID);
		} catch (MalformedJwtException e) {
			log.info("Invalid JWT token");
			log.trace("Invalid JWT token trace = {}", e);
			Responder.sendErrorResponse(response, ExceptionCode.TOKEN_MALFORMED);
		} catch (ExpiredJwtException e) {
			log.info("Expired JWT token");
			log.trace("Expired JWT token trace = {}", e);
			Responder.sendErrorResponse(response, ExceptionCode.TOKEN_EXPIRED);
		} catch (UnsupportedJwtException e) {
			log.info("Unsupported JWT token");
			log.trace("Unsupported JWT token trace = {}", e);
			Responder.sendErrorResponse(response, ExceptionCode.TOKEN_UNSUPPORTED);
		} catch (IllegalArgumentException e) {
			log.info("JWT claims string is empty.");
			log.trace("JWT claims string is empty trace = {}", e);
			Responder.sendErrorResponse(response, ExceptionCode.TOKEN_ILLEGAL_ARGUMENT);
		}
		return true;
	}

	public void accessTokenSetHeader(String accessToken, HttpServletResponse response){
		String headerValue = BEARER_PREFIX + accessToken;
		response.setHeader(AUTHORIZATION_HEADER,headerValue);
		log.info("# accessToken = {}",headerValue);
	}

	public void refreshTokenSetHeader(String refreshToken, HttpServletResponse response){
		response.setHeader("Refresh",refreshToken);
		log.info("# refreshToken = {}",refreshToken);
	}

	public ResponseCookie refreshTokenSetCookie(String refreshToken, HttpServletResponse response){
		return ResponseCookie.from("refreshToken", refreshToken)
				.maxAge(7 * 24 * 60 * 60) // days * hours * min * sec
				.path("/")
				.secure(true)
				.sameSite("None")
				.httpOnly(true)
				.build();
	}

	// Request Header Access Token 정보를 꺼내오는 메소드
	public String resolveToken(HttpServletRequest request) {
		String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
			return bearerToken.substring(7);
		}

		return null;
	}

	// 토큰 복호화, 예외발생(토큰만료, 시그니처오류)시 Claims 객체 안만들어짐.
	public Claims parseClaims(String token)  {
		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
}
