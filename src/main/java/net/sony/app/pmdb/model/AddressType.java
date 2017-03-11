/*
 * SCEE - PIN Point
 *
 * AddressType.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.model;
// ---- Import Statements -----------------------------------------------------

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 08:34
 */
@Entity
@Table(name="address_type")
public class AddressType {
    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------
    @Id
    @Column
    private String addressTypeCode;

    @Column
    private String addressTypeName;

    // ---- Constructors ------------------------------------------------------

    // ---- Other methods -----------------------------------------------------

    // ---- Bean Properties ---------------------------------------------------


    public String getAddressTypeCode() {
        return addressTypeCode;
    }

    public String getAddressTypeName() {
        return addressTypeName;
    }
}