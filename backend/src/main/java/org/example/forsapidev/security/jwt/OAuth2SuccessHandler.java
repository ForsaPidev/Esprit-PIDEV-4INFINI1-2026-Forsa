package org.example.forsapidev.security.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.forsapidev.Repositories.RoleRepository;
import org.example.forsapidev.Repositories.UserRepository;
import org.example.forsapidev.entities.UserManagement.ERole;
import org.example.forsapidev.entities.UserManagement.Role;
import org.example.forsapidev.entities.UserManagement.User;
import org.example.forsapidev.security.jwt.JwtUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Date;
import java.util.UUID;

public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtils jwtUtils;

    public OAuth2SuccessHandler(UserRepository userRepository,
                                RoleRepository roleRepository,
                                JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
    }
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();

        String email = oauthUser.getAttribute("email");
        String name = oauthUser.getAttribute("name");

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            user = new User();
            user.setUsername(name);
            user.setEmail(email);
            user.setIsActive(true);
            user.setCreatedAt(new Date());

            // Générer un mot de passe aléatoire hashé
            String randomPassword = UUID.randomUUID().toString();
            String hashedPassword = new BCryptPasswordEncoder().encode(randomPassword);
            user.setPasswordHash(hashedPassword);

            Role role = roleRepository.findByName(ERole.CLIENT)
                    .orElseThrow(() -> new RuntimeException("Role not found"));

            user.setRole(role);
            user.setAuthProvider("GOOGLE");
            userRepository.save(user);
        }

        String jwt = jwtUtils.generateJwtForUserId(user.getId());
        response.sendRedirect("https://bigotedly-youthful-dino.ngrok-free.dev/oauth-success?token=" + jwt);
    }
}