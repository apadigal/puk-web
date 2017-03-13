package net.sony.app.pmdb.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.Claim;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultJwtParser;
import io.jsonwebtoken.impl.crypto.MacProvider;
import lombok.extern.slf4j.Slf4j;
import net.sony.app.pmdb.model.Partner;
import net.sony.app.pmdb.security.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

import static io.jsonwebtoken.Jwts.parser;

/**
 * Created by swashtechltd on 12/03/2017.
 */
@CrossOrigin
@Slf4j
@RestController
@RequestMapping("/v1")
public class AuthorizeController extends AbstractController{

    private static final Key secret = MacProvider.generateKey(SignatureAlgorithm.HS256);
    private static final byte[] secretBytes = secret.getEncoded();
    private static final String base64SecretBytes = Base64.getEncoder().encodeToString(secretBytes);

    @Autowired
    SecretService secretService;

    @RequestMapping(value="/authorize", method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public String isAuthorized(@RequestHeader("Authorization") String strJWT) {
        log.debug("Request for Authorize Details :"+ strJWT);
        if(!strJWT.startsWith("Bearer"))
            throw new UnsupportedJwtException("Invalid Token");

        strJWT =  strJWT.split(" ")[1];

        JWT jwt = JWT.decode(strJWT);
        Map<String, Claim> claimMap = jwt.getClaims();
        if(claimMap.get("noonce") == null )
            throw new com.auth0.jwt.exceptions.InvalidClaimException("No nonce found in id token");


        log.debug(claimMap.toString());
        return claimMap.toString();
    }
}
