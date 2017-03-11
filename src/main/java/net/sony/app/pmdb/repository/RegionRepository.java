package net.sony.app.pmdb.repository;

import net.sony.app.pmdb.model.Region;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RegionRepository extends JpaRepository<Region, String> {
	
	public Region findByRegionCode(String RegionCode);

}

