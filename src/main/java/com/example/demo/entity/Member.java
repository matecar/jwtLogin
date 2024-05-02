package com.example.demo.entity;

import com.example.demo.security.UserRoleEnum;
import lombok.Getter;


@Getter
public class Member {


    private Long id;


    private String memberName;


    private String password;


    private UserRoleEnum role;

    public Member(String memberName, String password, UserRoleEnum role) {
        this.memberName = memberName;
        this.password = password;
        this.role = role;
    }

}
