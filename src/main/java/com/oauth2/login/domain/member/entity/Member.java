package com.oauth2.login.domain.member.entity;

import com.oauth2.login.global.common.auditing.BaseTime;
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
public class Member extends BaseTime {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "image")
    private String image;

    @Column(name = "password", unique = true)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> roles = new ArrayList<>();

    @Builder
    public Member(String username, String email, String image, String password, List<String> roles)  {
        this.username = username;
        this.email = email;
        this.image = image;
        this.password = password;
        this.roles = roles;
    }

    public Member oauthUpdate(String name, String email, String image, List<String> roles) {
        this.username = name;
        this.email = email;
        this.image = image;
        this.roles = roles;
        return this;
    }

}
