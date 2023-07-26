package com.example.springsecurityexam.auth;

import com.example.springsecurityexam.entity.User;
import com.example.springsecurityexam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PrincipalService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> find = repository.findByUsername(username);
        if(find.isPresent()){
            return new UserPrincipal(find.get());
        }else{
            throw new IllegalArgumentException("NOT EXIST USER");
        }
    }
}
