/* Taken from
 * https://gist.github.com/EmilHernvall/953733
 */

package com.android.signapk;

public class Base64 {
    public static String encode(byte[] data) {
        String tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        StringBuilder buffer = new StringBuilder();
        int pad = 0;
        for (int i = 0; i < data.length; i += 3) {

            int b = ((data[i] & 0xFF) << 16) & 0xFFFFFF;

            if (i + 1 < data.length) b |= (data[i+1] & 0xFF) << 8;
            else pad++;

            if (i + 2 < data.length) b |= (data[i+2] & 0xFF);
            else pad++;

            for (int j = 0; j < 4 - pad; j++) {
                int c = (b & 0xFC0000) >> 18;
                buffer.append(tbl.charAt(c));
                b <<= 6;
            }
        }
        for (int j = 0; j < pad; j++) buffer.append("=");

        return buffer.toString();
    }
}