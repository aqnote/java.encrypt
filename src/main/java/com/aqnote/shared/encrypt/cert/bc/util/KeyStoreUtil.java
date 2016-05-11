/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com>
 * Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.aqnote.com/licenses/LICENSE-1.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.aqnote.shared.encrypt.cert.bc.util;

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

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;

/**
 * KeyStoreUtil.java desc：TODO 
 * @author madding.lip May 30, 2014 4:17:31 PM
 */
public class KeyStoreUtil implements BCConstant {

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
