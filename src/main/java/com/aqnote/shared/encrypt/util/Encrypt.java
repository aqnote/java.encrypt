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

/**
 * 类Encrypt.java的实现描述：TODO 类实现描述 
 * @author madding.lip May 7, 2012 3:10:40 PM
 */
public  interface Encrypt {

    public String getAlgorithm();
    
    public String encrypt(String text);
    
    public String decrypt(String text);
    
    
    
}
