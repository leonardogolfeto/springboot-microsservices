package com.courses;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class CoursesApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void test(){
		System.out.println(new BCryptPasswordEncoder().encode("leo"));
	}

}
