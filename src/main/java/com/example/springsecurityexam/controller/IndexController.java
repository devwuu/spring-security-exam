package com.example.springsecurityexam.controller;

import com.example.springsecurityexam.entity.User;
import com.example.springsecurityexam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("home")
    public String home(){
        return "home";
    }



    @PostMapping("save")
    public ResponseEntity<User> save(@RequestBody User user){
        String encode = passwordEncoder.encode(user.password());
        user.password(encode);
        User saved = repository.save(user);
        return ResponseEntity.ok(saved);
    }

}
