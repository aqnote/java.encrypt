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
package com.aqnote.shared.encrypt.cert.jdk.util;

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
