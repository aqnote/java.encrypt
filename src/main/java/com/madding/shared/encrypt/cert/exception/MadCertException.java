package com.madding.shared.encrypt.cert.exception;

/**
 * MadCertException.java类描述：TODO
 * 
 * @author madding.lip
 */
public class MadCertException extends Exception {

    private static final long serialVersionUID = 2050009268351388382L;

    private Throwable         exp;

    public MadCertException(Throwable exp){
        this.exp = exp;
    }

    public String getMessage() {
        return exp.getMessage();
    }

    public Throwable getCause() {
        return exp.getCause();
    }

}
