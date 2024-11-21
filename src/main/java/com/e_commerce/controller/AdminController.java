package com.e_commerce.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {


    @GetMapping("/hello")
    public String hello(){
        return "Hello, Admin!";
    }
}
