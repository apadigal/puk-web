package net.sony.app.pmdb.repository;

import org.springframework.data.repository.Repository;

import net.sony.app.pmdb.model.PartnerCategory;

public interface PartnerCategoryRepository extends Repository<PartnerCategory, String>  {
	
	
	public PartnerCategory findByPartnerCategoryCode(String partnerCategoryCode);
   
}
