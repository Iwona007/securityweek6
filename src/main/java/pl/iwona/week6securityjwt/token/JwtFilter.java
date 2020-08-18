package pl.iwona.week6securityjwt.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {

        String authorization = httpServletRequest.getHeader("Authorization");
        System.out.println(authorization);

        String encodedPublicKey = httpServletRequest.getHeader("Certification");
        System.out.println(encodedPublicKey);

        RSAPublicKey publicKey = null;
        publicKey = getRsaPublicKey(encodedPublicKey, publicKey);

        DecodedJWT verify = getDecodedJWT(authorization, publicKey);

        Claim name = verify.getClaim("name");
        Claim role = verify.getClaim("role");

        SecurityContextHolder.getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(name.asString(),
                        "", Collections.singleton(new SimpleGrantedAuthority("ROLE_" + role.asString()))));
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private DecodedJWT getDecodedJWT(String authorization, RSAPublicKey publicKey) {
        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256(publicKey, null)).build();
        return jwtVerifier.verify(authorization.substring(7));
    }

    private RSAPublicKey getRsaPublicKey(String encodedPublicKey, RSAPublicKey publicKey) throws IOException {
        try {
            X509EncodedKeySpec keySpec =
                    new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            writeToFile("src/main/resources/ssh/publicKey.der", publicKey.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static void writeToFile(String path, byte[] key) throws IOException {
        File file = new File(path);
        file.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(key);
        fos.flush();
        fos.close();
    }

}
