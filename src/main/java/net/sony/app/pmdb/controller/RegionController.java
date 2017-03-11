/*
 * SCEE - PIN Point
 *
 * RegionController.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.controller;
// ---- Import Statements -----------------------------------------------------

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import net.sony.app.pmdb.model.Region;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 09:14
 */

@JsonAutoDetect
@RestController
@RequestMapping("/region")
public class RegionController extends AbstractController {
    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------

    @RequestMapping(method = RequestMethod.GET, produces = {APPLICATION_JSON})
    @ResponseStatus(HttpStatus.OK)
    public List<Region>  getRegion()
    {
        return regionRepository.findAll();
    }


}