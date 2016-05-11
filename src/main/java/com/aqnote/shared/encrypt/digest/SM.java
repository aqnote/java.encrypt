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
package com.aqnote.shared.encrypt.digest;

import static com.aqnote.shared.encrypt.cert.bc.constant.BCConstant.JCE_PROVIDER;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jcajce.provider.digest.SM3;
import org.bouncycastle.util.encoders.Hex;

import com.aqnote.shared.encrypt.ProviderUtil;

/**
 * SM.java 
 * 
 * http://www.oscca.gov.cn/UpFile/20101222141857786.pdf 
 * @author madding.lip Dec 24, 2015 6:13:41 PM
 */
public class SM {

    private static final String DEFAULT_CHARSET = "UTF-8";
    private static final String OID_SM3 = "1.2.156.197.1.401";
    
    static {
        ProviderUtil.addBCProvider();
    }
    
    public final static String sm3(String src) {
        if(StringUtils.isBlank(src)) return "";
        try {
            return sm3(src.getBytes(DEFAULT_CHARSET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }
    
    public final static String sm3(byte[] src) {
        if(src == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance(OID_SM3, JCE_PROVIDER);
            md.update(src);
            return new String(Hex.encode(md.digest()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return "";
    }
    
    public final static String _sm3(byte[] src) {
        if(src == null) return "";
        SM3.Digest md = new SM3.Digest();
        md.update(src);
        return new String(Hex.encode(md.digest()));
    }
    
    
}
