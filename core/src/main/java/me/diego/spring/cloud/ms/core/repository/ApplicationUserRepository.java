package me.diego.spring.cloud.ms.core.repository;

import me.diego.spring.cloud.ms.core.domain.ApplicationUser;
import me.diego.spring.cloud.ms.core.domain.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.Optional;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {
    Optional<ApplicationUser> findByUsername(String username);
}
