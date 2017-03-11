package net.sony.app.pmdb.model;

import lombok.*;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="party")
public class Party implements Serializable{

    private static final long serialVersionUID = -217148796887704030L;
    @Id
	@Column(name="party_level", nullable=false)
	private Integer partyLevel;
	
	@Column(nullable=false, length=48)
	private String partyLevelName;

}
