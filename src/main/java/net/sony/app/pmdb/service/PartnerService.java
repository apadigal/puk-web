/*
 * SCEE - PIN Point
 *
 * PartnerService.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.service;
// ---- Import Statements -----------------------------------------------------

import lombok.extern.slf4j.Slf4j;
import net.sony.app.pmdb.dto.PartnerDTO;
import net.sony.app.pmdb.exception.StaleDataException;
import net.sony.app.pmdb.model.Partner;
import net.sony.app.pmdb.model.PartnerCategory;
import net.sony.app.pmdb.model.Party;
import net.sony.app.pmdb.repository.PartnerRepository;
import org.hibernate.StaleObjectStateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 07/03/2017 $
 * Created Date: 07/03/2017 08:27
 */
@Slf4j
@Service
public class PartnerService {
    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------
    @Autowired
    private PartnerRepository partnerRepository;

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------
    public List<Partner> getPartners()
    {
        return partnerRepository.findAll();
    }

    public Partner getPartner(Integer guid)
    {
        return partnerRepository.getOne(guid);
    }

    @Transactional
    public void createPartner(PartnerDTO partnerDTO)
    {
        Partner partner = Partner.builder()
                .partnerName(partnerDTO.getPartnerName())
                .displayName(partnerDTO.getDisplayName())
                .party(partnerDTO.getParty())
                .partnerCategory(partnerDTO.getPartnerCategory())
                .partnerStatus(partnerDTO.getPartnerStatus())
                .createdBy(partnerDTO.getCreatedBy()).build();
        
        partnerRepository.save(partner);
    }

    @Transactional
    public void updatePartner(Partner partner)
    {
//        Partner partner = partnerRepository.findOne(partnerDTO.getGuid());
//        if(partner.getVersion() != partnerDTO.getVersion())
//        {
//            throw new StaleDataException("Stale data error");
//        }
//
//        partner

//        partner.setUpdatedBy(partnerDTO.getUpdatedBy());
//        partner.setPartnerCategory(partnerDTO.getPartnerCategory());
//        partner.setPartyLevel(partnerDTO.getPartyLevel());
//        partner.setPartnerStatus(partnerDTO.getPartnerStatus());
//        partner.setPartnerAddresses(partnerDTO.getPartnerAddresses());
//        partner.setVersion(partnerDTO.getVersion());

//        Partner partner = Partner.builder()
//                .guid(partnerDTO.getGuid())
//                .partnerName(partnerDTO.getPartnerName())
//                .displayName(partnerDTO.getDisplayName())
//                .partyLevel(partnerDTO.getPartyLevel())
//                .partnerCategory(partnerDTO.getPartnerCategory())
//                .partnerStatus(partnerDTO.getPartnerStatus())
//                .partnerAddresses(partnerDTO.getPartnerAddresses())
//                .updatedBy(partnerDTO.getUpdatedBy()).build();

        partnerRepository.save(partner);
    }

    public List<Partner> getPartnersByPartyLevel(Integer partyLevel)
    {
        return partnerRepository.findByParty(Party.builder().partyLevel(partyLevel).build());
    }


}