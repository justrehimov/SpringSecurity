package io.desofme.springsecurity.jwt;

import io.desofme.springsecurity.entity.User;
import io.desofme.springsecurity.service.UserService;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {

            if (request.getServletPath().startsWith("/api/user/login") || request.getServletPath().startsWith("/api/user/save")) {
                filterChain.doFilter(request, response);
            } else {
                String header = request.getHeader(HttpHeaders.AUTHORIZATION);
                String token = null;
                if (ObjectUtils.isEmpty(header) && !StringUtils.hasText(header)) {
                    throw new IllegalArgumentException("Authorization Header can't be empty");
                } else {
                    token = header.substring(7);
                    String username = jwtService.getUsernameFromToken(token);
                    UserDetails userDetails = userService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                }
            }
        }catch (JwtException ex){
            log.error("JWT token is not valid", ex);
        }catch (Exception ex){
            log.error("Error", ex);
        }
    }
}
