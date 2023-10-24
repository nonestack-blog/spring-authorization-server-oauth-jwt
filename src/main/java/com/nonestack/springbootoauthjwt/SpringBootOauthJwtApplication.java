package com.nonestack.springbootoauthjwt;

import com.nonestack.springbootoauthjwt.config.ApplicationConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ApplicationConfig.class)
public class SpringBootOauthJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootOauthJwtApplication.class, args);
    }

}
