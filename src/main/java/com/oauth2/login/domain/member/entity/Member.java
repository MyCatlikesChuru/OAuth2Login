package com.oauth2.login.domain.member.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "password", unique = true)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>();


    @Builder
    public Member(String username, String email, String password, List<String> roles)  {
        this.username = username;
        this.email = email;
        this.password = password;
        this.roles = roles;
    }

    public Member oauthUpdate(String name, String email, List<String> roles) {
        this.username = name;
        this.email = email;
        this.roles = roles;
        return this;
    }

}
