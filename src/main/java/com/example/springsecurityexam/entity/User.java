package com.example.springsecurityexam.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Entity
@Getter @Setter
@ToString
@EntityListeners(AuditingEntityListener.class)
@Accessors(chain = true)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role;

    private String provider; // 소셜로그인 시 어느 sns를 사용했는지
    private String providerId; // 소셜로그인 시 해당 sns의 id

    @CreatedDate
    private Instant createdAt;

}
