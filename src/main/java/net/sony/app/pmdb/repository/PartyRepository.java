package net.sony.app.pmdb.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import net.sony.app.pmdb.model.Partner;
import net.sony.app.pmdb.model.Party;

public interface PartyRepository extends JpaRepository<Party, Integer> {
	
	public Party findByPartyLevel(Integer partyLevel);

}

