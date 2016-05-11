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
 * Hex.java desc：TODO
 * 
 * @author madding.lip Dec 23, 2015 4:31:14 PM
 */
public class ByteUtil {

	// 用来将字节转换成 16 进制表示的字符
	private static char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
			'f' };

	public final static char[] toHexBytes(byte[] data) {
		if (data == null)
			return null;
		int len = data.length;
		char[] out = new char[len << 1];
		// two characters form the hex value.
		for (int i = 0, j = 0; i < len; i++) {
			out[j++] = hexDigits[(0xF0 & data[i]) >>> 4];
			out[j++] = hexDigits[0x0F & data[i]];
		}
		return out;
	}

	public final static String toHexString(byte[] data) {
		StringBuilder sb = new StringBuilder();
		if (data == null)
			return null;
		for (int i = 0; i < data.length; i++) {
			int value = data[i] & 0xFF;
			String hex = Integer.toHexString(value).toUpperCase();
			if (hex.length() < 2) {
				sb.append('0');
			}
			sb.append(hex);
		}
		return sb.toString();
	}
}
