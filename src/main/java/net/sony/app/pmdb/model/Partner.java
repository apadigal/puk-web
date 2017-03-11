package net.sony.app.pmdb.model;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;
import net.sony.app.pmdb.model.converter.PartnerCategoryConverter;
import net.sony.app.pmdb.model.converter.PartyLevelConverter;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Table(name = "partner")
public class Partner{

	private static final long serialVersionUID = -1914464160715944647L;
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Integer guid;

	@Column(nullable = false, length = 255)
	private String partnerName;

	@Column(nullable = false, length = 255)
	private String displayName;

	@ManyToOne
	@JoinColumn(name="party_level")
	@Convert(converter = PartyLevelConverter.class)
	private Party party;

	@ManyToOne
	@JoinColumn(nullable=false, name="partner_category_code")
	@Convert(converter=PartnerCategoryConverter.class)
	private PartnerCategory partnerCategory;
	
	@ManyToOne
	@JoinColumn(nullable=false, name="partner_status_code")
	private PartnerStatus partnerStatus;

	@OneToMany(cascade = CascadeType.ALL)
	@JoinColumn(name="guid")
	private Collection<PartnerAddress> partnerAddresses;
	
	@Column(nullable=true, length=64)
	private String updatedBy;

	@Column(nullable=false, length=64)
	private String createdBy;

	@Version
	private Integer version;

    @Column(nullable=false, updatable = false)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    @Temporal(TemporalType.TIMESTAMP)
	private Date createdAt;

	@Column(nullable = true)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    @Temporal(TemporalType.TIMESTAMP)
	private Date updatedAt;

	@PrePersist
	public void prePersist()
	{
        this.createdAt = Calendar.getInstance().getTime();
		if (this.partnerStatus == null)
		{
			this.partnerStatus = new PartnerStatus();
			this.partnerStatus.setPartnerStatusCode("ACTIVE");
		}
	}

    @PreUpdate
   	public void preUpdate()
   	{
   	    this.updatedAt = Calendar.getInstance().getTime();
   	}

}
