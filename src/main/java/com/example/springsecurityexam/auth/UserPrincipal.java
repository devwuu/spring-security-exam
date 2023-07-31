package com.example.springsecurityexam.auth;

import com.example.springsecurityexam.entity.User;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.*;

@ToString
public class UserPrincipal implements UserDetails {

    private final User user;

    public UserPrincipal(User user) {
        this.user = user;
    }

    public Long getId(){
        return user.id();
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Optional<List<String>> roles= user.getAllRoles();

        if(roles.isPresent()){
            Collection<GrantedAuthority> grantedAuthorities = roles.get()
                    .stream()
                    .map(r -> (GrantedAuthority) () -> r)
                    .collect(toList());
            return grantedAuthorities;
        }

        return Collections.EMPTY_LIST;
    }

    @Override
    public String getPassword() {
        return user.password();
    }

    @Override
    public String getUsername() {
        return user.username();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
