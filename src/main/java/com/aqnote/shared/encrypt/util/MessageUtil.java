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
package com.aqnote.shared.encrypt.util;

import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.ResourceBundle;

/**
 * 类MessageUtil.java的实现描述：和<code>ResourceBundle</code>及消息字符串有关的工具类
 *  
 * @author madding.lip May 7, 2012 5:43:48 PM
 */
public class MessageUtil {

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param params 参数表
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，或resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object[] params) {
        if ((bundle == null) || (key == null)) {
            return key;
        }

        try {
            String message = bundle.getString(key);

            return formatMessage(message, params);
        } catch (MissingResourceException e) {
            return key;
        }
    }

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param param1 参数1
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，则返回<code>null</code>。如果resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object param1) {
        return getMessage(bundle, key, new Object[] { param1 });
    }

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param param1 参数1
     * @param param2 参数2
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，则返回<code>null</code>。如果resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object param1, Object param2) {
        return getMessage(bundle, key, new Object[] { param1, param2 });
    }

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，则返回<code>null</code>。如果resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object param1,
        Object param2, Object param3) {
        return getMessage(bundle, key, new Object[] { param1, param2, param3 });
    }

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     * @param param4 参数4
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，则返回<code>null</code>。如果resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object param1,
        Object param2, Object param3, Object param4) {
        return getMessage(bundle, key, new Object[] { param1, param2, param3, param4 });
    }

    /**
     * 从<code>ResourceBundle</code>中取得字符串，并使用<code>MessageFormat</code>格式化字符串.
     *
     * @param bundle resource bundle
     * @param key 要查找的键
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     * @param param4 参数4
     * @param param5 参数5
     *
     * @return key对应的字符串，如果key为<code>null</code>或resource
     *         bundle为<code>null</code>，则返回<code>null</code>。如果resource key未找到，则返回<code>key</code>
     */
    public static String getMessage(ResourceBundle bundle, String key, Object param1,
        Object param2, Object param3, Object param4, Object param5) {
        return getMessage(bundle, key, new Object[] { param1, param2, param3, param4, param5 });
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param params 参数表
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object[] params) {
        if ((message == null) || (params == null) || (params.length == 0)) {
            return message;
        }

        return MessageFormat.format(message, params);
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param param1 参数1
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object param1) {
        return formatMessage(message, new Object[] { param1 });
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param param1 参数1
     * @param param2 参数2
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object param1, Object param2) {
        return formatMessage(message, new Object[] { param1, param2 });
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object param1, Object param2, Object param3) {
        return formatMessage(message, new Object[] { param1, param2, param3 });
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     * @param param4 参数4
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object param1, Object param2, Object param3,
        Object param4) {
        return formatMessage(message, new Object[] { param1, param2, param3, param4 });
    }

    /**
     * 使用<code>MessageFormat</code>格式化字符串.
     *
     * @param message 要格式化的字符串
     * @param param1 参数1
     * @param param2 参数2
     * @param param3 参数3
     * @param param4 参数4
     * @param param5 参数5
     *
     * @return 格式化的字符串，如果message为<code>null</code>，则返回<code>null</code>
     */
    public static String formatMessage(String message, Object param1, Object param2, Object param3,
        Object param4, Object param5) {
        return formatMessage(message, new Object[] { param1, param2, param3, param4, param5 });
    }
    
    public static String getMessage(Properties props, String key, Object param) {
        return getMessage(props, key, new Object[] { param });
    }
    
    public static String getMessage(Properties props, String key, Object[] params) {
        if ((props == null) || (key == null)) {
            return key;
        }

        try {
            String message = props.getProperty(key);
            return formatMessage(message, params);
        } catch (MissingResourceException e) {
            return key;
        }
    }
}

