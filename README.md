![display](https://repository-images.githubusercontent.com/709512356/8a8a9e95-760c-4f45-ae50-e1e676e5b0b3)

Spring Authorization Server OAuth (JWT) that uses Spring Security and Spring Security OAuth2 Resource. Applying the new way to configure OAuth JWT without the need of writing a customized filter.

## <a name="what-you-will-build" aria-label="what-you-will-build" id="what-you-will-build" href="#what-you-will-build"></a>What You Will build
Spring Authorization Server OAuth that uses JWT Token

## <a name="what-you-need" aria-label="what-you-need" id="what-you-need" href="#what-you-need"></a>What You Need
- A favorite text editor or IDE
- JDK 1.8 or later
- Gradle 4+ or Maven 3.2+

## <a name="setup-project-with-spring-initializr" aria-label="setup-project-with-spring-initializr" id="setup-project-with-spring-initializr" href="#setup-project-with-spring-initializr"></a>Setup Project With Spring Initializr

- Navigate to https://start.spring.io

- define the project name example: `spring-authorization-server-oauth-jwt`
- Choose Project **Maven** and the language  **Java**.
- Choose Your **Java** version ex: **17**
- Click add dependencies and select:
    - Spring Web
    - Spring Security
    - Spring Oauth2 Resource Server
    - Spring Data JPA
    - H2 Database
    - Lombok
    - Rest Assured

- Click Generate.

Unzip the Downloaded Zip and open the Project using your favorite text editor or IDE


## <a name="start-the-implementation" aria-label="start-the-implementation" id="start-the-implementation" href="#start-the-implementation"></a>Start the implementation
- Define The Permission Entity
```java
@Entity(name = "Permission")
@Table(name = "permissions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

}
```

- Define the User Entity and override the implemented methods from the **UserDetails** interface 
```java
@Entity(name = "User")
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    private String email;

    private String password;

    private boolean active;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "users_permissions",
        joinColumns = @JoinColumn(name = "users_id"),
        inverseJoinColumns = @JoinColumn(name = "permissions_id"))
    public List<Permission> permissions = new ArrayList<>();

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream()
            .map(Permission::getName)
            .map(SimpleGrantedAuthority::new)
            .toList();
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    @JsonIgnore
    @Override
    public String getUsername() {
        return email;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return active;
    }
}
```
Define the User Repository and the Query **findOneByEmailAndActive**, we are going to use it for retrieving the user object when we try to authenticate

```java
@Repository
public interface UserRepository  extends JpaRepository<User, Long> {

    @Query("select u from User u where u.email = :email and u.active = true")
    Optional<User> findOneByEmailAndActive(String email);

}

```
- Define the User Details Service `@Service` implementation that will manage user authentication.
- The annotation `@RequiredArgsConstructor` is a lombok annotation used to generate a constructor with required attributes 
```java
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findOneByEmailAndActive(email)
            .orElseThrow(() -> new UsernameNotFoundException("Email address does not exist"));
    }

}
```

- Define the Spring Security Configuration

```java
@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    /**
     * Define the password encoder.
     *
     * @return {@link BCryptPasswordEncoder}
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Define the filer chain.
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // Enable cors & disable CSRF
        http.cors(withDefaults()).csrf(AbstractHttpConfigurer::disable);

        // Set session management to stateless
        http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Set unauthorized requests exception handler
        http.exceptionHandling( exceptionHandling -> exceptionHandling
            .authenticationEntryPoint((request, response, ex) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage()))
            .accessDeniedHandler((request, response, ex) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage()))
        );

        // Set the secured endpoints and the permitted endpoints
        http.authorizeHttpRequests((authz) ->
            authz
                // Our public endpoints *
                .requestMatchers("/api/authenticate").permitAll()
                // Our private endpoints
                .anyRequest().authenticated());

        // Add The JWT token filter
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }

}
```

- Define the Spring JWT Security Configuration

```java
@Log4j2
@Configuration
@RequiredArgsConstructor
public class SecurityJwtConfiguration {

    private final ApplicationConfig config;

    /**
     * The JWT Decoder.
     *
     * @return {@link JwtDecoder}
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(getSecretKey()).macAlgorithm(SecurityService.JWT_ALGORITHM).build();
        return token -> {
            try {
                return jwtDecoder.decode(token);
            } catch (Exception e) {
                log.error(e.getMessage());
            }
            return null;
        };
    }

    /**
     * The JWT Decoder.
     *
     * @return {@link JwtEncoder}
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(getSecretKey()));
    }

    /**
     * The Jwt Authentication converter
     *
     * @return JwtAuthenticationConverter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        grantedAuthoritiesConverter.setAuthoritiesClaimName(SecurityService.AUTHORITIES_KEY);
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    /**
     * Get the Secret key.
     *
     * @return {@link SecretKey}
     */
    private SecretKey getSecretKey() {
        byte[] keyBytes = Base64.from(config.getSecurity().getKey()).decode();
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, SecurityService.JWT_ALGORITHM.getName());
    }

}
```

- Define the Security Service, used to generate a new token from an authentication object

```java
@Service
@RequiredArgsConstructor
public class SecurityService {

    public static final MacAlgorithm JWT_ALGORITHM = MacAlgorithm.HS512;
    public static final String AUTHORITIES_KEY = "auth";
    private final JwtEncoder jwtEncoder;
    private final ApplicationConfig config;

    public String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

        Instant now = Instant.now();
        Instant validity = now.plus(config.getSecurity().getValidity(), ChronoUnit.SECONDS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
            .issuedAt(now)
            .expiresAt(validity)
            .subject(authentication.getName())
            .claim(AUTHORITIES_KEY, authorities)
            .build();

        JwsHeader jwsHeader = JwsHeader.with(JWT_ALGORITHM).build();
        return this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
    }

}
```

- Define the Authenticate Controller

```java
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthenticateController {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final SecurityService securityService;

    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authorize(@RequestBody LoginDTO loginDTO) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
            loginDTO.getEmail(),
            loginDTO.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = securityService.createToken(authentication);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(jwt);
        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }

}
```

- Define the Secured Controller

```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class SecuredController {

    private final UserRepository userRepository;

    @GetMapping("/me")
    public User getAuth(HttpServletRequest request) {
        return userRepository.findOneByEmailAndActive(request.getRemoteUser())
            .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }

}
```

- Create `data.sql` under the resources folder to populate our table

```sql
INSERT INTO PERMISSIONS (ID, NAME)
VALUES (1, 'read'),
       (2, 'write');

INSERT INTO USERS (ID, NAME, EMAIL, PASSWORD, ACTIVE)
VALUES (1, 'john doe', 'john.doe@example.com', '$2a$12$x1pibFM7OeLeq..7/9rEkewNsSokhPIx7saguQsLg/jheUI2EBOEG', true);

INSERT INTO USERS_PERMISSIONS (USERS_ID, PERMISSIONS_ID)
VALUES (1, 1);

When running the application, by default the `data.sql` will be executed before the entity creation into the database, to prevent that add the following property under the `application.properties`
```
- Update the `application.yml` with the following properties

```yml
spring:
    jpa:
        defer-datasource-initialization: true
        show-sql: true

app:
    security:
        key: 'NWM3NDhkOTM5NDc4MTgyMTdiZDdmMzM5NjIyOTRkM2U4YWU2MzkyNDM3YjNlNzc3MzA3Yjg0MDA3MGU5MzEzZWY4ZjhiMGQ5MGYyOTU0YjUyNTJhOTliMzMzMWExOWRhNGUyNWVhMWE5ZWY3MzY0ZjYwMTRiNjNhZDQ0ZTkzNDA'
        validity: 3600
```

## <a name="run" aria-label="run" id="run" href="#run"></a>Run

Run the Java application as a `SpringBootApplication` with your IDE or use the following command line

```shell
 ./mvnw spring-boot:run
```
Now, you can open the URL below on your browser, default port is `8080` you can set it under the `application.yml`

## <a name="testing" aria-label="testing" id="testing" href="#testing"></a>Testing

Write some test cases to test the authentication flow that work correctly
- Test 1 : check the authentication and retrieve JWT token
- Test 2 : try to access a secured resource to get the authenticated user detail

```java
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
```

## <a name="summary" aria-label="summary" id="summary" href="#summary"></a>Summary

Congratulations 🎉 ! You've created a Spring Authorization Server OAuth that uses JWT Token using Spring Security & Spring OAuth2 Resource

## <a name="github" aria-label="github" id="github" href="#github"></a>Github
The tutorial can be found here on [GitHub](https://github.com/nonestack-blog/spring-authorization-server-oauth-jwt) 👋

## <a name="blog" aria-label="blog" id="blog" href="#blog"></a>Blog
Check new tutorials on [nonestack](https://www.nonestack.com) 👋
