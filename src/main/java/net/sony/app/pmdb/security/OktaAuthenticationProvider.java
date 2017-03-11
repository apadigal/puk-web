/*
 * SCEE - PIN Point
 *
 * OktaAuthenticationProvider.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.security;
// ---- Import Statements -----------------------------------------------------

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 10/03/2017 $
 * Created Date: 10/03/2017 15:50
 */
public class OktaAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }

    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------

    // ---- Bean Properties ---------------------------------------------------

}