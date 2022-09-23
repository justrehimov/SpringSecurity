package io.desofme.springsecurity.controller;

import io.desofme.springsecurity.entity.Role;
import io.desofme.springsecurity.entity.User;
import io.desofme.springsecurity.repositroy.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/save")
    public User user(@RequestBody User user){
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        List<Role> roles = Arrays.asList(new Role(1L,"ADMIN"));
        user.setRoles(roles);
        return userRepository.save(user);
    }

    @GetMapping("/list")
    public List<User> list(){
        return userRepository.findAll();
    }

    @GetMapping("/{id}")
    public User getById(@PathVariable Long id){
        return userRepository.findById(id)
                .orElse(null);
    }
}
