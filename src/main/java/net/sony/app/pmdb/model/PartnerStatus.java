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
@Table(name = "partner_status")
public class PartnerStatus implements Serializable{

	private static final long serialVersionUID = -9180193308178750524L;
	@Id
	@Column
	private String partnerStatusCode;
	
	@Column
	private String partnerStatusName;
}
