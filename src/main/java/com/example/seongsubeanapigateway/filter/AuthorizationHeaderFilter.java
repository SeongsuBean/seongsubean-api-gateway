package com.example.seongsubeanapigateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter
    extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

  Environment environment;

  // JWT Properties
  private static final String SECRET = "oopsw";
  private static final String TOKEN_PREFIX = "Bearer ";
  private static final String HEADER_STRING = "Authorization";


  public AuthorizationHeaderFilter(Environment environment) {
    super(Config.class);
    this.environment = environment;
  }

  public static class Config {

    private Set<String> allowedRoles = new HashSet<>();
    private boolean requireAuth = true;

    public Set<String> getAllowedRoles() {
      return allowedRoles;
    }

    public void setAllowedRoles(Set<String> allowedRoles) {
      this.allowedRoles = allowedRoles;
    }

    public boolean isRequireAuth() {
      return requireAuth;
    }

    public void setRequireAuth(boolean requireAuth) {
      this.requireAuth = requireAuth;
    }
  }

  private static final Map<String, Integer> ROLE_HIERARCHY = Map.of(
      "GUEST", 0,      // 비회원
      "CUSTOMER", 1,   // 고객
      "OWNER", 2,      // 사장
      "ADMIN", 3       // 관리자
  );

  //login ->token ->user(with token) -> header(include token)
  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();
      String path = request.getURI().getPath();
      String method = request.getMethod().name();

      // 인증이 필요없는 경로 체크
      if (!config.isRequireAuth()) {
        log.info("No authentication required for path: {}", path);
        return chain.filter(exchange);
      }

      // Authorization 헤더 확인
      if (!request.getHeaders().containsKey(HEADER_STRING)) {
        return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
      }

      String authorizationHeader = request.getHeaders().get(HEADER_STRING).get(0);

      // Bearer 토큰 형식 확인
      if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX)) {
        return onError(exchange, "Invalid authorization header format", HttpStatus.UNAUTHORIZED);
      }

      String token = authorizationHeader.replace(TOKEN_PREFIX, "");

      // JWT 토큰 검증 및 정보 추출
      DecodedJWT decodedJWT = validateTokenAndGetClaims(token);
      if (decodedJWT == null) {
        return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
      }

      // 토큰 만료 확인
      if (isTokenExpired(decodedJWT)) {
        return onError(exchange, "JWT token is expired", HttpStatus.UNAUTHORIZED);
      }

      // 사용자 역할 추출
      String userRole = decodedJWT.getClaim("role").asString();
      String userId = decodedJWT.getSubject();

      if (userRole == null || userRole.isEmpty()) {
        return onError(exchange, "No role information in token", HttpStatus.FORBIDDEN);
      }

      // 역할 기반 접근 제어
      if (!hasPermission(userRole, config.getAllowedRoles())) {
        return onError(exchange,
            String.format("Insufficient permissions. Required: %s, User role: %s",
                config.getAllowedRoles(), userRole), HttpStatus.FORBIDDEN);
      }

      // 사용자 정보를 헤더에 추가 (다운스트림 서비스에서 사용 가능)
      ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
          .header("X-User-Id", userId)
          .header("X-User-Role", userRole)
          .header("X-User-Name", decodedJWT.getClaim("username").asString())
          .build();

      log.info("User: {} with role: {} accessing: {} {}", userId, userRole, method, path);

      return chain.filter(exchange.mutate().request(mutatedRequest).build());
    };
  }

  private DecodedJWT validateTokenAndGetClaims(String token) {
    try {
      return JWT.require(Algorithm.HMAC512(SECRET))
          .build()
          .verify(token);
    } catch (Exception ex) {
      log.error("JWT validation failed: {}", ex.getMessage());
      return null;
    }
  }

  private boolean isTokenExpired(DecodedJWT decodedJWT) {
    try {
      Date expiredDate = decodedJWT.getExpiresAt();
      log.info("Expired JWT: {}", expiredDate);
      log.info(new Date(System.currentTimeMillis()).toString());
      return expiredDate.before(new Date(System.currentTimeMillis()));
    } catch (Exception e) {
      log.error("Error checking token expiration: {}", e.getMessage());
      return true;
    }
  }

  private boolean hasPermission(String userRole, Set<String> allowedRoles) {
    if (allowedRoles.isEmpty()) {
      return true; // 빈 세트면 모든 인증된 사용자 허용
    }

    Integer userRoleLevel = ROLE_HIERARCHY.get(userRole);
    if (userRoleLevel == null) {
      log.warn("Unknown role: {}", userRole);
      return false;
    }

    // 허용된 역할 중 하나라도 사용자 역할 레벨보다 낮거나 같으면 허용
    return allowedRoles.stream()
        .map(ROLE_HIERARCHY::get)
        .filter(Objects::nonNull)
        .anyMatch(allowedLevel -> userRoleLevel >= allowedLevel);
  }

  private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    log.error(err);

    String errorMessage = switch (httpStatus) {
      case UNAUTHORIZED -> "Authentication required";
      case FORBIDDEN -> "Access denied";
      default -> "Request failed";
    };

    // JSON 형태로 에러 메시지 반환
    String jsonError = String.format(
        "{\"error\":\"%s\",\"message\":\"%s\",\"timestamp\":%d}",
        httpStatus.getReasonPhrase(),
        errorMessage,
        System.currentTimeMillis()
    );

    response.getHeaders().add("Content-Type", "application/json");
    byte[] bytes = jsonError.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
    return response.writeWith(Flux.just(buffer));
  }
}