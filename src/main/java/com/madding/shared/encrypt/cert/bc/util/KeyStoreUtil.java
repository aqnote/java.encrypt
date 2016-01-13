/*
 * Programmer-tools -- A develop code for dever to quickly analyse
 * Copyright (C) 2013-2016 madding.lip <madding.lip@gmail.com>.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation;
 */
package com.madding.shared.encrypt.cert.bc.util;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;

/**
 * KeyStoreUtil.java desc：TODO 
 * @author madding.lip May 30, 2014 4:17:31 PM
 */
public class KeyStoreUtil implements MadBCConstant {

    public static KeyStore getPKCS12KeyStore(String alias, Certificate[] certChain, KeyPair keyPair, char[] passwd) throws Exception {

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) keyPair.getPrivate();
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        SubjectKeyIdentifier pubKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, pubKeyId);
        KeyStore store = KeyStore.getInstance(KEY_STORE_TYPE, JCE_PROVIDER);
        store.load(null, null);
        store.setKeyEntry(alias, keyPair.getPrivate(), passwd, certChain);
        return store;
    }
    
    public static KeyStore readPKCS12KeyStore(String alias, Certificate[] chain, KeyPair keyPair, char[] pwd) throws Exception {
        PKCS12SafeBagBuilder BagBuilder = new JcaPKCS12SafeBagBuilder((X509Certificate)chain[0]);
        BagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(alias));
        SubjectKeyIdentifier pubKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        BagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);
        
        KeyStore store = KeyStore.getInstance(KEY_STORE_TYPE, JCE_PROVIDER);
        store.load(null, null);
        store.setKeyEntry(alias, keyPair.getPrivate(), pwd, chain);

        return store;
    }
}
