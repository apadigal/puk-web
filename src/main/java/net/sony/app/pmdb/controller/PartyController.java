package net.sony.app.pmdb.controller;

import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import net.sony.app.pmdb.model.Partner;
import net.sony.app.pmdb.model.Party;

@CrossOrigin
@Slf4j
@RestController
@RequestMapping("/party")
public class PartyController extends AbstractController{

    @RequestMapping(method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public List<Party> getParty() {
        log.debug("in getPartyLevel");
        return partyService.getPartyList();
    }
    
    @RequestMapping(value="/{partyLevel}", method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public Party getParty(@PathVariable Integer partyLevel) {
        log.debug("in getPartyPartners :"+ partyLevel);
        return partyService.getParty(partyLevel);
    }

    @RequestMapping(value="/{partyLevel}/partner", method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public List<Partner> getPartnersByPartyLevel(@PathVariable Integer partyLevel) {
        log.debug("in getPartyPartners :"+ partyLevel);
        return partnerService.getPartnersByPartyLevel(partyLevel);
    }
    

}