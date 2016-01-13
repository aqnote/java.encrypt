package com.madding.shared.encrypt.cert.dataobject;

import java.io.Serializable;
import java.util.Date;

import com.alibaba.fastjson.JSON;

/**
 * 类MadPureCertDo.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Nov 17, 2013 10:59:28 PM
 */
public class MadCertDo implements Serializable {

    private static final long serialVersionUID = 815492566333086681L;

    private String            certFile;

    private String            p12File;
    private String            p12Pwd;

    private long              serialNumber;
    private String            issuerDN;
    private String            subjectDN;
    private Date              notBefore;
    private Date              notAfter;

    private String            keyFile;
    private String            keyPwd;

    public String getCertFile() {
        return certFile;
    }

    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public String getP12File() {
        return p12File;
    }

    public void setP12File(String p12File) {
        this.p12File = p12File;
    }

    public String getP12Pwd() {
        return p12Pwd;
    }

    public void setP12Pwd(String p12Pwd) {
        this.p12Pwd = p12Pwd;
    }

    public void setSerialNumber(long serialNumber) {
        this.serialNumber = serialNumber;
    }

    public long getSerialNumber() {
        return serialNumber;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setKeyPwd(String keyPwd) {
        this.keyPwd = keyPwd;
    }

    public String getKeyPwd() {
        return keyPwd;
    }
    
    public String toString() {
        return JSON.toJSONString(this);
    }

}
