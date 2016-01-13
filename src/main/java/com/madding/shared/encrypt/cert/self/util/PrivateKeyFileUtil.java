package com.madding.shared.encrypt.cert.self.util;

import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.lang.StringUtils;

/**
 * 类PrivateKeyTool.java的实现描述：私钥处理类
 * 
 * @author madding.lip Nov 18, 2013 12:01:35 PM
 */
public class PrivateKeyFileUtil {

    public static void writeKeyFile(String b64Key, String keyfile) throws IOException {

        if (StringUtils.isBlank(b64Key) || StringUtils.isBlank(keyfile)) {
            return;
        }
        FileOutputStream fos2 = new FileOutputStream(keyfile);
        fos2.write(b64Key.getBytes());
        fos2.flush();
        fos2.close();
    }
}
