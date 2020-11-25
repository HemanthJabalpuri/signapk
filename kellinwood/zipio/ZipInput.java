/*
 * Copyright (C) 2010 Ken Ellinwood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kellinwood.zipio;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.LinkedHashMap;
import java.util.Map;

public class ZipInput {

    public String inputFilename;
    RandomAccessFile in = null;
    long fileLength;
    int scanIterations = 0;

    Map<String,ZioEntry> zioEntries = new LinkedHashMap<String,ZioEntry>();
    CentralEnd centralEnd;

    private static boolean align;

    public static boolean toAlign() {
        return align;
    }

    public ZipInput(String filename) throws IOException {
        this.inputFilename = filename;
        in = new RandomAccessFile(new File(inputFilename), "r");
        fileLength = in.length();
    }

    public static ZipInput read(String filename, boolean toAlign) throws IOException {
        ZipInput zipInput = new ZipInput(filename);
        align = toAlign;
        zipInput.doRead();
        return zipInput;
    }

    public Map<String,ZioEntry> getEntries() {
        return zioEntries;
    }

    /** Scan the end of the file for the end of central directory record (EOCDR).
        Returns the file offset of the EOCD signature.  The size parameter is an
        initial buffer size (e.g., 256).
     */
    public long scanForEOCDR(int size) throws IOException {
        if (size > fileLength || size > 65536) throw new IllegalStateException("End of central directory not found in " + inputFilename);

        int scanSize = (int)Math.min(fileLength, size);

        byte[] scanBuf = new byte[scanSize];

        in.seek(fileLength - scanSize);

        in.readFully(scanBuf);

        for (int i = scanSize - 22; i >= 0; i--) {
            scanIterations += 1;
            if (scanBuf[i] == 0x50 && scanBuf[i+1] == 0x4b && scanBuf[i+2] == 0x05 && scanBuf[i+3] == 0x06) {
                return fileLength - scanSize + i;
            }
        }

        return scanForEOCDR(size * 2);
    }

    private void doRead() {
        try {
            long posEOCDR = scanForEOCDR(256);
            in.seek(posEOCDR);
            centralEnd = CentralEnd.read(this);

            in.seek(centralEnd.centralStartOffset);

            for (int i = 0; i < centralEnd.totalCentralEntries; i++) {
                ZioEntry entry = ZioEntry.read(this);
                zioEntries.put(entry.getName(), entry);
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    public void close() {
        if (in != null) try { in.close(); } catch (Throwable t) {}
    }

    public long getFilePointer() throws IOException {
        return in.getFilePointer();
    }

    public void seek(long position) throws IOException {
        in.seek(position);
    }

    public int readInt() throws IOException{
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result |= (in.readUnsignedByte() << (8 * i));
        }
        return result;
    }

    public short readShort() throws IOException {
        short result = 0;
        for (int i = 0; i < 2; i++) {
            result |= (in.readUnsignedByte() << (8 * i));
        }
        return result;
    }

    public String readString(int length) throws IOException {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++) {
            buffer[i] = in.readByte();
        }
        return new String(buffer);
    }

    public byte[] readBytes(int length) throws IOException {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++) {
            buffer[i] = in.readByte();
        }
        return buffer;
    }
}
