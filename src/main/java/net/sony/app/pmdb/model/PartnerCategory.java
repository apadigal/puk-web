package net.sony.app.pmdb.model;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="partner_category")
public class PartnerCategory implements Serializable{

	private static final long serialVersionUID = 2918950662435601211L;
	@Id
	@Column
	private String partnerCategoryCode;
	
	@Column
	private String partnerCategoryName;
}
