package io.desofme.springsecurity.auth;

import io.desofme.springsecurity.entity.User;
import io.desofme.springsecurity.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public LoginResponse login(LoginRequest loginRequest) {
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            User user = (User) authentication.getPrincipal();
            String accessToken = jwtService.getToken(user);
            LoginResponse loginResponse = new LoginResponse(accessToken, user.getId());
            return loginResponse;

        }catch (Exception ex){
            throw new AuthenticationCredentialsNotFoundException("Username or password is invalid");
        }

    }
}
