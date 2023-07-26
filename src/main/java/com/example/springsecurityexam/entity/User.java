package com.example.springsecurityexam.entity;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Optional;

@Entity
@Getter @Setter
@Accessors(chain = true, fluent = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
@ToString
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String roles;

    public Optional<List<String>> getAllRoles(){
        if(!ObjectUtils.isEmpty(roles)){
            return Optional.of(List.of(roles.split("\\|")));
        }else{
            return Optional.empty();
        }
    }

}
