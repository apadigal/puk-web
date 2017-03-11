package net.sony.app.pmdb.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import net.sony.app.pmdb.model.PartnerCategory;

@Converter
public class PartnerCategoryConverter implements AttributeConverter<PartnerCategory, String>{

	@Override
	public String convertToDatabaseColumn(PartnerCategory partnerCategory) {
		// TODO Auto-generated method stub
		return partnerCategory.getPartnerCategoryCode();
	}

	@Override
	public PartnerCategory convertToEntityAttribute(String partnerCategoryCode) {
		// TODO Auto-generated method stub
		PartnerCategory partnerCategory = new PartnerCategory();
		partnerCategory.setPartnerCategoryCode(partnerCategoryCode);
		return partnerCategory;
	}
	
	

}
