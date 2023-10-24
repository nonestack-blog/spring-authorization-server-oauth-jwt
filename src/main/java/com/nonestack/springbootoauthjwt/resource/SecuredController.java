package com.nonestack.springbootoauthjwt.resource;

import com.nonestack.springbootoauthjwt.domain.User;
import com.nonestack.springbootoauthjwt.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
