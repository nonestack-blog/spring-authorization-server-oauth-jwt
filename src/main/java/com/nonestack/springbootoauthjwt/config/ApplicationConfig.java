package com.nonestack.springbootoauthjwt.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app", ignoreUnknownFields = false)
@Getter
@Setter
public class ApplicationConfig {

    private Security security = new Security();


    @Getter
    @Setter
    public static class Security {
        private String key;
        private Long validity;
    }
}
