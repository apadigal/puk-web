package net.sony.app.pmdb.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Getter
@Setter
@MappedSuperclass
public class TransactionEntity implements Serializable{

    private static final long serialVersionUID = 2409410001625948542L;

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
	}
	
	@PreUpdate
	public void preUpdate()
	{
		this.updatedAt = Calendar.getInstance().getTime();
	}

}
