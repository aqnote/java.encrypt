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
package com.aqnote.shared.encrypt.util.log;

/**
 * 类LogAgg.java的实现描述：日志聚合
 * 
 * @author madding.lip Nov 25, 2013 2:17:28 PM
 */
public class LogAgg {

    public static enum R {
        F, T;
    }

    public static final String COLON_SEP = ":";

    public static String MSG(R result, String method, String... infos) {
        R tmp = (result == null) ? R.T : result;
        StringBuilder sb = new StringBuilder(tmp.name());
        sb.append(COLON_SEP + method);
        for (String info : infos) {
            sb.append(COLON_SEP + info);
        }
        return sb.toString();
    }
}
