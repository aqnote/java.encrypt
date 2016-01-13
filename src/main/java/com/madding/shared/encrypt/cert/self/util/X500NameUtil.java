package com.madding.shared.encrypt.cert.self.util;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.x509.X500Name;

import com.madding.shared.encrypt.lang.MessageUtil;

/**
 * 类X500Name.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 11:11:30 PM
 */
public class X500NameUtil {
    private static final Logger logger = LoggerFactory.getLogger(X500NameUtil.class);

    private static final String ISSUE_STRING       = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN=device,  Email=madding.lip@gmail.com";
    private static final String SUBJECT_Pattern    = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN={0},  Email={1}";
    private static final String SUBJECT_PatternExt = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN={0},  Email={1}, T={2}";

    public static X500Name      issueName          = null;

    public static X500Name getIssueName() {
        if (issueName == null) {
            try {
                issueName = new X500Name(ISSUE_STRING);
            } catch (IOException e) {
                logger.error("create issusX500Name error, System.exit(-1)", e);
            }
        }
        return issueName;
    }

    public static X500Name getSubjectName(String cn, String email) {
        X500Name subjectName = null;
        String subjectString = MessageUtil.formatMessage(SUBJECT_Pattern, new String[] { cn, email });
        try {
            subjectName = new X500Name(subjectString);
        } catch (IOException e) {
            logger.error("create issusX500Name error, System.exit(-1)", e);
        }
        return subjectName;
    }
    
    public static X500Name getSubjectName(String cn, String email, String title) {
        X500Name subjectName = null;
        String subjectString = MessageUtil.formatMessage(SUBJECT_PatternExt, new String[] { cn, email, title});
        try {
            subjectName = new X500Name(subjectString);
        } catch (IOException e) {
            logger.error("create issusX500Name error, System.exit(-1)", e);
        }
        return subjectName;
    }
}
