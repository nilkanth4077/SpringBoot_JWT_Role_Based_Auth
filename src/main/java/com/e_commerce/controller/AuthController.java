package com.e_commerce.controller;

import com.e_commerce.dto.LoginRequest;
import com.e_commerce.dto.LoginResponse;
import com.e_commerce.entity.User;
import com.e_commerce.exception.UserException;
import com.e_commerce.repository.UserRepo;
import com.e_commerce.service.UserService;
import com.e_commerce.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepo userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, UserRepo userRepository, UserService userService,
                          PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        String token = jwtUtil.generateToken(authentication.getName(),
                authentication.getAuthorities().iterator().next().getAuthority());

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(token);
        String role = authentication.getAuthorities().iterator().next().getAuthority();
        loginResponse.setRole(role);
        return ResponseEntity.ok(loginResponse);
    }

    @GetMapping("/profile")
    public Optional<User> getProfileByToken(@RequestHeader("Authorization") String authorizationHeader) throws UserException {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            return userService.getProfileByToken(token);
        } else {
            throw new UserException("Invalid Authorization header");
        }
    }
}
