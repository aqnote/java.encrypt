package com.madding.shared.encrypt.log;

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
