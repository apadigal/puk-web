/*
 * SCEE - PIN Point
 *
 * PartyService.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.service;
// ---- Import Statements -----------------------------------------------------

import lombok.extern.slf4j.Slf4j;
import net.sony.app.pmdb.model.Party;
import net.sony.app.pmdb.repository.PartyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 07/03/2017 $
 * Created Date: 07/03/2017 12:31
 */
@Slf4j
@Service
public class PartyService {
    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------
    @Autowired
    private PartyRepository partyRepository;

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------
    public List<Party> getPartyList()
    {
        log.debug("in getPartyList()");
        return partyRepository.findAll();
    }

    public Party getParty(Integer partyLevel)
    {
        log.debug("in getPartyLevel :"+ partyLevel);

        return partyRepository.getOne(partyLevel);
    }

    // ---- Bean Properties ---------------------------------------------------

}