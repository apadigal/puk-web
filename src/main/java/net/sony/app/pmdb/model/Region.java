/*
 * SCEE - PIN Point
 *
 * Region.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.model;
// ---- Import Statements -----------------------------------------------------

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 08:36
 */
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table
public class Region implements Serializable {
    private static final long serialVersionUID = 5558140595011229802L;
    // ---- Static ------------------------------------------------------------

    // ---- Constants ---------------------------------------------------------

    // ---- Member Variables --------------------------------------------------
    @Id
    @Column
    private String regionCode;

    @Column
    private  String regionName;

}