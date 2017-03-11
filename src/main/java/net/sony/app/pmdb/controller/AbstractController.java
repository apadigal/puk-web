/*
 * SCEE - PIN Point
 *
 * AbstractControllers.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.controller;
// ---- Import Statements -----------------------------------------------------

import com.fasterxml.jackson.databind.JsonMappingException;
import lombok.extern.slf4j.Slf4j;
import net.sony.app.pmdb.repository.AddressTypeRepository;
import net.sony.app.pmdb.repository.RegionRepository;
import net.sony.app.pmdb.service.PartnerService;
import net.sony.app.pmdb.service.PartyService;
import org.hibernate.StaleObjectStateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 09:12
 */
@Slf4j
public class AbstractController {
    // ---- Static ------------------------------------------------------------
    protected static final String APPLICATION_JSON = "application/json";

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------

    @Autowired
    protected PartnerService partnerService;
    
    @Autowired
    protected PartyService partyService;

    @Autowired
    protected RegionRepository regionRepository;

    @Autowired
    protected AddressTypeRepository addressTypeRepository;

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------

    // ---- Exception Handling -----------------------------------------------------
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(StaleObjectStateException.class)
    @ResponseBody
    public String handleStaleObjectStateException(StaleObjectStateException exception) {
        log.error(exception.getMessage(), exception);
        return "ERROR : Stale Data - Already updated by another user";
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(JsonMappingException.class)
    public String handleJsonMappingException(JsonMappingException exception)
    {
        log.error(exception.getMessage(), exception);
        return "ERROR : Invalid data format received";
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public String handleMessageNotReadableException(HttpMessageNotReadableException exception)
    {
          log.error(exception.getMessage(), exception);
          return  "ERROR: Invalid data received";
    }

    @RequestMapping(path = "/error", produces = APPLICATION_JSON)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleError()
    {
        return "Unexpected Error";
    }

}