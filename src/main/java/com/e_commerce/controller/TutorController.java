package com.e_commerce.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/tutor")
@PreAuthorize("hasRole('TUTOR')")
public class TutorController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello, Tutor!";
    }
}
