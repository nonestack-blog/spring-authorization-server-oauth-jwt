package com.nonestack.springbootoauthjwt;

import com.nonestack.springbootoauthjwt.secruity.SecurityService;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.util.Collections;

import static org.apache.http.entity.ContentType.APPLICATION_JSON;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ImportAutoConfiguration({SecurityService.class})
public class AuthenticateTest {

    @LocalServerPort
    private int port;
    public static final String TOKEN_URL = "/api/authenticate";
    public static final String AUTH_URL = "/api/me";
    public static final String EMAIL = "john.doe@example.com";
    public static final String PASSWORD = "password";

    @Autowired
    private SecurityService securityService;

    @Test
    public void authenticateAndGetJWTToken() throws JSONException {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("email", EMAIL);
        jsonObject.put("password", PASSWORD);

        Response response = RestAssured
            .given()
            .contentType(APPLICATION_JSON.getMimeType())
            .body(jsonObject.toString())
            .post("http://localhost:" + port + TOKEN_URL);

        assertThat(response.jsonPath().getString("jwt_token")).isNotBlank();
    }

    @Test
    public void checkTheAuthenticatedUser() {
        String token = getToken();
        Response response = RestAssured
            .given()
            .header("Authorization", "bearer " + token)
            .get("http://localhost:" + port + AUTH_URL);

        assertThat(response.jsonPath().getString("email")).isEqualTo(EMAIL);
    }

    public String getToken() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(EMAIL, null, Collections.emptyList());
        return securityService.createToken(authenticationToken);
    }

}
