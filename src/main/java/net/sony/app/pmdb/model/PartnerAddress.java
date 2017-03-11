/*
 * SCEE - PIN Point
 *
 * PartnerAddress.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.model;
// ---- Import Statements -----------------------------------------------------


import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.temporal.TemporalField;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 08:30
 */
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "partner_address")
public class PartnerAddress implements Serializable {
    private static final long serialVersionUID = -4786479843353047005L;

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer partnerAddressId;

    @Column
    private Integer guid;

    @ManyToOne
    @JoinColumn(nullable=false, name="address_type_code")
    private AddressType addressType;

    @ManyToOne
    @JoinColumn(nullable = false, name="region_code")
    private Region region;

    @Column(nullable = false, length = 64)
    private String addressLine1;

    @Column(length = 64)
    private String addressLine2;

    @Column(nullable = false, length = 64)
    private String cityTownCountry;

    @Column(length = 64)
    private String state;

    @Column(length = 20)
    private String zipPostCode;

    @Column(length = 1)
    private String isActive;

    @Column(nullable = false, length = 20)
    private String userId;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    private Date effectiveDate;

    @Column(nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    private Date inactiveDate;

    @Column(nullable = false, updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    private Date createdAt;

    @Column(nullable = true)
    @Temporal(TemporalType.TIMESTAMP)
//    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm a z")
    private Date updatedAt;

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------

    // ---- Bean Properties ---------------------------------------------------


    @PrePersist
    public void prePersist()
    {
        if (this.isActive == null)
        {
            this.isActive = "Y";
        }
        this.createdAt = Calendar.getInstance().getTime();
    }

    @PreUpdate
    public void preUpdate()
    {
        this.updatedAt = Calendar.getInstance().getTime();
    }

    public Integer getPartnerAddressId() {
        return partnerAddressId;
    }

    public void setPartnerAddressId(Integer partnerAddressId) {
        this.partnerAddressId = partnerAddressId;
    }

    public Integer getGuid() {
        return guid;
    }

    public void setGuid(Integer guid) {
        this.guid = guid;
    }

    public AddressType getAddressType() {
        return addressType;
    }

    public void setAddressType(AddressType addressType) {
        this.addressType = addressType;
    }

    public Region getRegion() {
        return region;
    }

    public void setRegion(Region region) {
        this.region = region;
    }

    public String getAddressLine1() {
        return addressLine1;
    }

    public void setAddressLine1(String addressLine1) {
        this.addressLine1 = addressLine1;
    }

    public String getAddressLine2() {
        return addressLine2;
    }

    public void setAddressLine2(String addressLine2) {
        this.addressLine2 = addressLine2;
    }

    public String getCityTownCountry() {
        return cityTownCountry;
    }

    public void setCityTownCountry(String cityTownCountry) {
        this.cityTownCountry = cityTownCountry;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getZipPostCode() {
        return zipPostCode;
    }

    public void setZipPostCode(String zipPostCode) {
        this.zipPostCode = zipPostCode;
    }

    public String getIsActive() {
        return isActive;
    }

    public void setIsActive(String isActive) {
        this.isActive = isActive;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Date getEffectiveDate() {
        return effectiveDate;
    }

    public void setEffectiveDate(Date effectiveDate) {
        this.effectiveDate = effectiveDate;
    }

    public Date getInactiveDate() {
        return inactiveDate;
    }

    public void setInactiveDate(Date inactiveDate) {

        this.inactiveDate = inactiveDate;
    }

    public Date getCreatedAt() {

        return createdAt;
    }

    public void setCreatedAt(Date createdAt)
    {
        this.createdAt = createdAt;
    }

    public Date getUpdatedAt() {

        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {

        this.updatedAt = updatedAt;
    }
}