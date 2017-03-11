/*
 * SCEE - PIN Point
 *
 * StaleDataException.java
 *
 * ©2008 SCEE. All Rights Reserved
 */
// ---- Package ---------------------------------------------------------------
package net.sony.app.pmdb.exception;
// ---- Import Statements -----------------------------------------------------

/**
 * Created by IntelliJ IDEA.
 * $Revision: #1 $
 *
 * @Author: apadigal $
 * $Date: 08/03/2017 $
 * Created Date: 08/03/2017 16:10
 */
public class StaleDataException extends RuntimeException {
    private static final long serialVersionUID = -5906488352593391014L;

    public StaleDataException(){super();}

    public StaleDataException(String errorMessage){
        super(errorMessage);
    }

    public StaleDataException(String errorMessage, Throwable cause)
    {
        super(errorMessage, cause);
    }

    public StaleDataException(Throwable cause)
    {
        super(cause);
    }



}