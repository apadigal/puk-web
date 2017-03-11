package net.sony.app.pmdb.controller;

import java.util.List;

import net.sony.app.pmdb.dto.PartnerDTO;
import net.sony.app.pmdb.model.PartnerAddress;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import lombok.extern.slf4j.Slf4j;
import net.sony.app.pmdb.model.Partner;

@CrossOrigin
@Slf4j
@RestController
@RequestMapping("/partners")
public class PartnerController extends AbstractController{

    @RequestMapping(method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public List<Partner> getPartners() {

        log.debug("Request for Partner List :");
        return partnerService.getPartners();
    }

    @RequestMapping(value="/{guid}", method = RequestMethod.GET, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public Partner getPartner(@PathVariable Integer guid) {
        log.debug("Request for Partner Details :"+ guid);
        return partnerService.getPartner(guid);
    }

    @RequestMapping(method = RequestMethod.POST, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.CREATED)
    public void createPartner(@RequestBody PartnerDTO partnerDTO) {
    	
    	log.debug("in createPartner :"+ partnerDTO.toString());
        partnerService.createPartner(partnerDTO);

    }

    @RequestMapping(value="/{guid}",method = RequestMethod.PUT, produces = { APPLICATION_JSON })
    @ResponseStatus(HttpStatus.OK)
    public void updatePartner(@RequestBody Partner partner) {

        log.debug("Update Request :"+ partner.getGuid());
        partnerService.updatePartner(partner);

    }
}