/*
 * SCEE - PIN Point
 *
 * AddressTypeRepository.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.repository;
// ---- Import Statements -----------------------------------------------------

import net.sony.app.pmdb.model.AddressType;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 03/03/2017 $
 * Created Date: 03/03/2017 09:09
 */
public interface AddressTypeRepository extends JpaRepository<AddressType, String> {


}