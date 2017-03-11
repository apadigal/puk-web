package net.sony.app.pmdb.model.converter;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

import net.sony.app.pmdb.model.Party;


@Converter
public class PartyLevelConverter implements AttributeConverter<Party, Integer>{

	@Override
	public Integer convertToDatabaseColumn(Party party) {
		// TODO Auto-generated method stub
		return party.getPartyLevel();
	}

	@Override
	public Party convertToEntityAttribute(Integer partyLevel) {
		// TODO Auto-generated method stub
		Party party = new Party();
		party.setPartyLevel(partyLevel);
		return party;
	}
	
	

}
