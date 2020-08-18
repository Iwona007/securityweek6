package pl.iwona.week6securityjwt.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {

        String authorization = httpServletRequest.getHeader("Authorization");
        System.out.println(authorization);

        String encodPublicKey = httpServletRequest.getHeader("Certification");
        System.out.println(encodPublicKey);
//        Base64.Decoder decoder = Base64.getDecoder();
        PublicKey publicKey = null;

        try {
            X509EncodedKeySpec keySpec =
                    new X509EncodedKeySpec(Base64.getDecoder().decode(encodPublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256((RSAPublicKey) publicKey, null)).build();
        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
        Claim name = verify.getClaim("name");

        boolean isAdmin = verify.getClaim("admin").asBoolean();
        String role = "ROLE_USER";
        if (isAdmin) {
            role = "ROLE_ADMIN";
        }

        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(name.asString(),
                "", Collections.singleton(new SimpleGrantedAuthority("ROLE_" + role))));
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
