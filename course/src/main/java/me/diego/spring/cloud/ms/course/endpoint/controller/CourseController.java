package me.diego.spring.cloud.ms.course.endpoint.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.diego.spring.cloud.ms.core.domain.ApplicationUser;
import me.diego.spring.cloud.ms.core.domain.Course;
import me.diego.spring.cloud.ms.course.endpoint.service.CourseService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Tag(name = "Course", description = "Manage courses")
@RestController
@RequestMapping("/v1/admin/course")
@Slf4j
@RequiredArgsConstructor
public class CourseController {

    private final CourseService courseService;

    @Operation(
            summary = "Retrieve a page of course",
            description = "Retrieve a page of course, need to be authenticated"
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = { @Content(schema = @Schema(implementation = Course[].class), mediaType = "application/json") }),
            @ApiResponse(responseCode = "401", content = { @Content(schema = @Schema()) })})
    @GetMapping
    public ResponseEntity<Page<Course>> list(Pageable pageable) {
        return ResponseEntity.ok(courseService.list(pageable));
    }
}
