package com.example.demo.repository;

import com.example.demo.entity.Member;

import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository  {
    Optional<Member> findByMemberName(String memberName);
}