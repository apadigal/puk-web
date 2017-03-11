package net.sony.app.pmdb.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import net.sony.app.pmdb.model.Partner;
import net.sony.app.pmdb.model.PartnerCategory;
import net.sony.app.pmdb.model.PartnerStatus;
import net.sony.app.pmdb.model.Party;

public interface PartnerRepository extends JpaRepository<Partner, Integer> {
	
	public List<Partner> findByParty(Party party);
	
	public List<Partner> findByPartnerCategory(PartnerCategory partnerCategory);
	
	public List<Partner> findByPartnerStatus(PartnerStatus partnerStatus);
	
}
