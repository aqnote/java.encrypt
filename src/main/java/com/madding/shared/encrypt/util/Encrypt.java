/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.util;

/**
 * 类Encrypt.java的实现描述：TODO 类实现描述 
 * @author madding.lip May 7, 2012 3:10:40 PM
 */
public  interface Encrypt {

    public String getAlgorithm();
    
    public String encrypt(String text);
    
    public String decrypt(String text);
    
    
    
}
