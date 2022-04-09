package peaksoft.api;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import peaksoft.author.AuthenticationRequest;
import peaksoft.config.JwtUtil;
import peaksoft.dto.UserResponse;
import peaksoft.service.UserService;

@RestController
@AllArgsConstructor
@RequestMapping("/login")
public class Controller {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtil jwtUtil;


    @PostMapping
    public ResponseEntity<?> authentication(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(),
                    authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username and password", e);
        }
        final UserDetails userDetails = userService.loadUserByUsername(authenticationRequest.getUserName());
        final String token = jwtUtil.generatedToken(userDetails);

        return ResponseEntity.ok(new UserResponse(token));
    }
}
