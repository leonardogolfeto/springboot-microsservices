package com.courses.endpoint.controller;

import com.courses.endpoint.service.CourseService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.core.model.Course;

@RestController
@RequestMapping("v1/admin/course")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CourseController {
    private final CourseService service;

    @GetMapping
    public ResponseEntity<Iterable<Course>> list(Pageable pageable){
        return new ResponseEntity<>(service.list(pageable), HttpStatus.OK);
    }
}
