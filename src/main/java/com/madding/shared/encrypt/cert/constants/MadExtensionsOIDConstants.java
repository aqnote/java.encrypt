package com.madding.shared.encrypt.cert.constants;

/**
 * 类MadExtensionsOIDConstants.java的实现描述：证书常量类
 * 
 * @author madding.lip Nov 19, 2013 4:16:09 PM
 */
public class MadExtensionsOIDConstants {

    public static final String PREFIX              = "1.1.1.1.2.";

    public static final String SUFFIX              = ".30";

    public static final String EXT_OSLOGINAME_OID  = PREFIX + "3" + SUFFIX;

    public static final String EXT_OSTYPE_OID      = PREFIX + "4" + SUFFIX;

    public static final String EXT_EMPLOYEE_OID    = PREFIX + "11" + SUFFIX;
    public static final String EXT_UMID_OID        = PREFIX + "12" + SUFFIX;
    public static final String EXT_MAC_OID         = PREFIX + "13" + SUFFIX;

    // iso.org.dod.internet.private.enterprise
    public static final String ST_PREFIX           = "1.3.6.1.4.1";
    // Decimal Organization Contact Email
    public static final String AL_SUFFIX           = ST_PREFIX + ".19621";
    // user defined intermediate
    public static final String INTERMEDIATE_SUFFIX = AL_SUFFIX + ".31";

    public static final String ALI_OSLOGINAME_OID  = INTERMEDIATE_SUFFIX + "3";
    public static final String ALI_OSTYPE_OID      = INTERMEDIATE_SUFFIX + "4";
    public static final String ALI_EMPLOYEE_OID    = INTERMEDIATE_SUFFIX + "11";
    public static final String ALI_UMID_OID        = INTERMEDIATE_SUFFIX + "12";
    public static final String ALI_MAC_OID         = INTERMEDIATE_SUFFIX + "13";

}
