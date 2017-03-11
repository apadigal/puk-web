package net.sony.app.pmdb.dto;

import lombok.*;
import net.sony.app.pmdb.model.*;

import java.io.Serializable;
import java.util.Collection;

@Getter
@Setter
@Builder
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class PartnerDTO implements Serializable{

    private static final long serialVersionUID = 4284514057809612350L;
    private Integer guid;
    private String partnerName;
	private String displayName;
	private Integer partyLevel;
	private String partnerCategoryCode;
	private String partnerStatusCode;

	private Party party;
	private PartnerCategory partnerCategory;
	private PartnerStatus partnerStatus;
   	private String updatedBy;
   	private String createdBy;
   	private Integer version;

   	private Collection<PartnerAddress> partnerAddresses;

   	public PartnerCategory getPartnerCategory()
    {
        if (this.partnerCategory != null)
            return partnerCategory;
        else if(partnerCategory != null)
            return PartnerCategory.builder().partnerCategoryCode(partnerCategoryCode).build();
        else
            return null;
    }

    public Party getParty()
    {
        if(this.party != null)
            return this.party;
        else if(partyLevel != null)
            return Party.builder().partyLevel(this.partyLevel).build();
        else
            return null;
    }

    public PartnerStatus getPartnerStatus()
    {
        if(this.partnerStatus != null)
            return this.partnerStatus;
        else if(this.partnerStatusCode != null)
            return PartnerStatus.builder().partnerStatusCode(partnerStatusCode).build();
        else
            return null;
    }
}
