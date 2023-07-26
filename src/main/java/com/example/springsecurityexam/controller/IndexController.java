package com.example.springsecurityexam.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1")
public class IndexController {

    @GetMapping("home")
    public String home(){
        return "home";
    }

    @PostMapping("save")
    public String save(){
        return "save";
    }

}
