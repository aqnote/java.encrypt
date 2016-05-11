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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;

import org.apache.commons.lang.StringUtils;

/**
 * 类StreamUtil.java的实现描述： 基于流的工具类. 部分方法移植自IBM developer works精彩文章, 参见package文档.
 * 
 * @author madding.lip May 7, 2012 4:08:44 PM
 */
public class StreamUtil {

    private static final int DEFAULT_BUFFER_SIZE = 8192;

    /**
     * 从输入流读取内容, 写入到输出流中. 此方法使用大小为8192字节的默认的缓冲区.
     * 
     * @param in 输入流
     * @param out 输出流
     * @throws IOException 输入输出异常
     */
    public static void io(InputStream in, OutputStream out) throws IOException {
        io(in, out, -1);
    }

    /**
     * 从输入流读取内容, 写入到输出流中. 使用指定大小的缓冲区.
     * 
     * @param in 输入流
     * @param out 输出流
     * @param bufferSize 缓冲区大小(字节数)
     * @throws IOException 输入输出异常
     */
    public static void io(InputStream in, OutputStream out, int bufferSize) throws IOException {
        if (bufferSize == -1) {
            bufferSize = DEFAULT_BUFFER_SIZE;
        }

        byte[] buffer = new byte[bufferSize];
        int amount;

        while ((amount = in.read(buffer)) >= 0) {
            out.write(buffer, 0, amount);
        }
    }

    /**
     * 从输入流读取内容, 写入到输出流中. 此方法使用大小为4096字符的默认的缓冲区.
     * 
     * @param in 输入流
     * @param out 输出流
     * @throws IOException 输入输出异常
     */
    public static void io(Reader in, Writer out) throws IOException {
        io(in, out, -1);
    }

    /**
     * 从输入流读取内容, 写入到输出流中. 使用指定大小的缓冲区.
     * 
     * @param in 输入流
     * @param out 输出流
     * @param bufferSize 缓冲区大小(字符数)
     * @throws IOException 输入输出异常
     */
    public static void io(Reader in, Writer out, int bufferSize) throws IOException {
        if (bufferSize == -1) {
            bufferSize = DEFAULT_BUFFER_SIZE >> 1;
        }

        char[] buffer = new char[bufferSize];
        int amount;

        while ((amount = in.read(buffer)) >= 0) {
            out.write(buffer, 0, amount);
        }
    }

    /**
     * 取得同步化的输出流.
     * 
     * @param out 要包裹的输出流
     * @return 线程安全的同步化输出流
     */
    public static OutputStream synchronizedOutputStream(OutputStream out) {
        return new SynchronizedOutputStream(out);
    }

    /**
     * 取得同步化的输出流.
     * 
     * @param out 要包裹的输出流
     * @param lock 同步锁
     * @return 线程安全的同步化输出流
     */
    public static OutputStream synchronizedOutputStream(OutputStream out, Object lock) {
        return new SynchronizedOutputStream(out, lock);
    }

    /**
     * 将指定输入流的所有文本全部读出到一个字符串中.
     * 
     * @param in 要读取的输入流
     * @return 从输入流中取得的文本
     * @throws IOException 输入输出异常
     */
    public static String readText(InputStream in) throws IOException {
        return readText(in, null, -1);
    }

    /**
     * 将指定输入流的所有文本全部读出到一个字符串中.
     * 
     * @param in 要读取的输入流
     * @param encoding 文本编码方式
     * @return 从输入流中取得的文本
     * @throws IOException 输入输出异常
     */
    public static String readText(InputStream in, String encoding) throws IOException {
        return readText(in, encoding, -1);
    }

    /**
     * 将指定输入流的所有文本全部读出到一个字符串中.
     * 
     * @param in 要读取的输入流
     * @param encoding 文本编码方式
     * @param bufferSize 缓冲区大小(字符数)
     * @return 从输入流中取得的文本
     * @throws IOException 输入输出异常
     */
    public static String readText(InputStream in, String encoding, int bufferSize) throws IOException {
        Reader reader = (encoding == null) ? new InputStreamReader(in) : new InputStreamReader(in, encoding);

        return readText(reader, bufferSize);
    }

    /**
     * 将指定<code>Reader</code>的所有文本全部读出到一个字符串中.
     * 
     * @param reader 要读取的<code>Reader</code>
     * @return 从<code>Reader</code>中取得的文本
     * @throws IOException 输入输出异常
     */
    public static String readText(Reader reader) throws IOException {
        return readText(reader, -1);
    }

    /**
     * 将指定<code>Reader</code>的所有文本全部读出到一个字符串中.
     * 
     * @param reader 要读取的<code>Reader</code>
     * @param bufferSize 缓冲区的大小(字符数)
     * @return 从<code>Reader</code>中取得的文本
     * @throws IOException 输入输出异常
     */
    public static String readText(Reader reader, int bufferSize) throws IOException {
        StringWriter writer = new StringWriter();
        io(reader, writer, bufferSize);
        return writer.toString();
    }

    public static byte[] stream2Bytes(InputStream is) throws IOException {
        int total = is.available();
        byte[] bs = new byte[total];
        is.read(bs);
        return bs;
    }

    public static String stream2Bytes(InputStream is, Charset charset) {
        String result = null;
        try {
            int total = is.available();
            byte[] bs = new byte[total];
            is.read(bs);
            result = new String(bs, charset.name());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static InputStream bytes2Stream(byte[] bs) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(bs);
        return inputStream;
    }

    public static InputStream bytes2Stream(String text, Charset charset) throws UnsupportedEncodingException {
        ByteArrayInputStream inputStream = null;
        if (StringUtils.isBlank(text)) {
            return null;
        }
        byte[] bs = text.getBytes(charset.name());
        inputStream = new ByteArrayInputStream(bs);
        return inputStream;
    }

    public static String reader2String(InputStream is) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(is));
        StringBuffer buffer = new StringBuffer();
        String line = " ";
        while ((line = in.readLine()) != null) {
            buffer.append(line);
        }
        return buffer.toString();
    }

    public static void close(InputStream is) {
        try {
            if (is != null) is.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void close(OutputStream os) {
        try {
            if (os != null) os.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void close(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void close(ServerSocket ssocket) {
        try {
            if (ssocket != null && !ssocket.isClosed()) ssocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void close(Reader reader) {
        try {
            if (reader != null) reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 同步化的输出流包裹器.
     */
    private static class SynchronizedOutputStream extends OutputStream {

        private OutputStream out;
        private Object       lock;

        SynchronizedOutputStream(OutputStream out){
            this(out, out);
        }

        SynchronizedOutputStream(OutputStream out, Object lock){
            this.out = out;
            this.lock = lock;
        }

        public void write(int datum) throws IOException {
            synchronized (lock) {
                out.write(datum);
            }
        }

        public void write(byte[] data) throws IOException {
            synchronized (lock) {
                out.write(data);
            }
        }

        public void write(byte[] data, int offset, int length) throws IOException {
            synchronized (lock) {
                out.write(data, offset, length);
            }
        }

        public void flush() throws IOException {
            synchronized (lock) {
                out.flush();
            }
        }

        public void close() throws IOException {
            synchronized (lock) {
                out.close();
            }
        }
    }
}
