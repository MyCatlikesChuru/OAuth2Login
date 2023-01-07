package com.oauth2.login.domain.member.controller;

import com.oauth2.login.domain.member.controller.dto.ApiTestDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthTestController {

    @GetMapping("/test")
    public ResponseEntity createSomething(){

        log.info("# test api 실행");

        return new ResponseEntity(HttpStatus.OK);
    }

    @PostMapping("/make")
    public ResponseEntity createSomething(@RequestBody ApiTestDto apiTestDto){

        log.info("# make api 실행");

        return new ResponseEntity(HttpStatus.CREATED);
    }

}
