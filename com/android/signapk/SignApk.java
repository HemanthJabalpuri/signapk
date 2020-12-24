/*
 * Taken from https://android.googlesource.com/platform/build/+/e691373514d47ecf29ce13e14e9f3b867d394693/tools/signapk/
 *
 * Copyright (C) 2008 The Android Open Source Project
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

package com.android.signapk;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Command line tool to sign OTA updates in
 * a way compatible with the mincrypt verifier, using SHA1 and RSA keys.
 */
class SignApk {

    private static void signWholeOutputFile(OutputStream outputStream,
                                            byte[] sbtbytes,
                                            Signature signature)
        throws IOException, GeneralSecurityException {

        ByteArrayOutputStream temp = new ByteArrayOutputStream();

        // put a readable message and a null char at the start of the
        // archive comment, so that tools that display the comment
        // (hopefully) show something sensible.
        // TODO: anything more useful we can put in this message?
        byte[] message = "signed by SignApk".getBytes("UTF-8");
        temp.write(message);
        temp.write(0);
        temp.write(sbtbytes);
        temp.write(signature.sign());
        int total_size = temp.size() + 6;
        if (total_size > 0xffff) {
            throw new IllegalArgumentException("signature is too big for ZIP file comment");
        }
        // signature starts this many bytes from the end of the file
        int signature_start = total_size - message.length - 1;
        temp.write(signature_start & 0xff);
        temp.write((signature_start >> 8) & 0xff);
        // Why the 0xff bytes?  In a zip file with no archive comment,
        // bytes [-6:-2] of the file are the little-endian offset from
        // the start of the file to the central directory.  So for the
        // two high bytes to be 0xff 0xff, the archive would have to
        // be nearly 4GB in size.  So it's unlikely that a real
        // commentless archive would have 0xffs here, and lets us tell
        // an old signed archive from a new one.
        temp.write(0xff);
        temp.write(0xff);
        temp.write(total_size & 0xff);
        temp.write((total_size >> 8) & 0xff);
        temp.flush();

        // Signature verification checks that the EOCD header is the
        // last such sequence in the file (to avoid minzip finding a
        // fake EOCD appended after the signature in its scan).  The
        // odds of producing this sequence by chance are very low, but
        // let's catch it here if it does.
        byte[] b = temp.toByteArray();
        for (int i = 0; i < b.length-3; ++i) {
            if (b[i] == 0x50 && b[i+1] == 0x4b && b[i+2] == 0x05 && b[i+3] == 0x06) {
                throw new IllegalArgumentException("found spurious EOCD header at " + i);
            }
        }

        outputStream.write(total_size & 0xff);
        outputStream.write((total_size >> 8) & 0xff);
        temp.writeTo(outputStream);
    }

    private static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int chunkSize;
        while ((chunkSize = in.read(buf)) != -1)
            result.write(buf, 0, chunkSize);
        return result.toByteArray();
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: signapk input.jar output.jar");
            System.exit(2);
        }

        RandomAccessFile inputFile = null;
        FileOutputStream outputFile = null;

        try {
            inputFile = new RandomAccessFile(args[0], "r");

            // For a zip with no archive comment, the
            // end-of-central-directory record will be 22 bytes long, so
            // we expect to find the EOCD marker 22 bytes from the end.
            byte[] tail = new byte[22];
            inputFile.seek(inputFile.length() - 22);
            inputFile.readFully(tail);
            if (tail[0] != 0x50 || tail[1] != 0x4b || tail[2] != 0x05 || tail[3] != 0x06) {
                throw new IllegalArgumentException("zip data already has an archive comment");
            }

            byte[] pk8bytes = toByteArray(SignApk.class.getResourceAsStream("/keys/testkey.pk8"));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pk8bytes));
            outputFile = new FileOutputStream(args[1]);

            Signature wfsig = Signature.getInstance("SHA1withRSA");
            wfsig.initSign(privateKey);

            int read;
            inputFile.seek(0);
            byte[] buffer = new byte[4096];
            long len = inputFile.length() - 2;
            while ((read = inputFile.read(buffer, 0, len < buffer.length ? (int) len : buffer.length)) > 0) {
                outputFile.write(buffer, 0, read);
                wfsig.update(buffer, 0, read);
                len -= read;
            }

            byte[] sbtbytes = toByteArray(SignApk.class.getResourceAsStream("/keys/testkey.sbt"));
            signWholeOutputFile(outputFile, sbtbytes, wfsig);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        } finally {
            try {
                if (inputFile != null) inputFile.close();
                if (outputFile != null) outputFile.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
