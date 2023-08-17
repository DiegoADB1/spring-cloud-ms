package me.diego.spring.cloud.ms.discovery.core.repository;

import me.diego.spring.cloud.ms.discovery.core.domain.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}
