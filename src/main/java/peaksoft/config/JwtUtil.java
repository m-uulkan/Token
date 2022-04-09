package peaksoft.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    @Value("${secret}")
    private String secret;

    private final  long  JWT_TOKEN_VALIDITY=30*24*60*1000l;//1month

    public String getUsernameFromToken(String token){
       return  getClaimFromToken(token, Claims::getSubject);
    }
 private <T> T getClaimFromToken(String token, Function<Claims,T>claimResolver){
      final Claims claims=getAllClaimsFromToken(token);
      return claimResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().
                setSigningKey(secret).
                parseClaimsJws(token).
                getBody();
    }

    private Boolean isTokenExpired(String token){
        final Date expiration=getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token,Claims::getExpiration);
    }

    public String generatedToken(UserDetails userDetails){
        Map<String,Object> claims=new HashMap<>();
        return createToken(claims,userDetails.getUsername());

    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+JWT_TOKEN_VALIDITY))
                .signWith(SignatureAlgorithm.HS512,secret)
                .compact();
    }
    public Boolean Validate(String token,UserDetails userDetails){
        final String username=getUsernameFromToken(token);
                return username.equals(userDetails.getUsername())&& !isTokenExpired(token);
    }
}