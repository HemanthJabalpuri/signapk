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
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

import kellinwood.zipio.ZioEntry;
import kellinwood.zipio.ZipInput;
import kellinwood.zipio.ZipOutput;

/**
 * Command line tool to sign JAR files (including APKs and OTA updates) in
 * a way compatible with the mincrypt verifier, using SHA1 and RSA keys.
 */
class SignApk {
    private static final String CERT_SF_NAME = "META-INF/CERT.SF";
    private static final String CERT_RSA_NAME = "META-INF/CERT.RSA";

    private static final String OTACERT_NAME = "META-INF/com/android/otacert";

    // Files matching this pattern are not copied to the output.
    private static Pattern stripPattern =
        Pattern.compile("^(META-INF/((.*)[.](SF|RSA|DSA|EC)|com/android/otacert))|(" +
                        Pattern.quote(JarFile.MANIFEST_NAME) + ")$");

    /** Add the SHA1 of every file to the manifest, creating it if necessary. */
    private static Manifest addDigestsToManifest(ZipInput jar)
            throws IOException, GeneralSecurityException {
        Manifest input = null;
        Map<String, ZioEntry> entries = jar.getEntries();
        ZioEntry manifestEntry = entries.get(JarFile.MANIFEST_NAME);
        if (manifestEntry != null) {
            input = new Manifest();
            input.read(manifestEntry.getInputStream());
        }
        Manifest output = new Manifest();
        Attributes main = output.getMainAttributes();
        if (input != null) {
            main.putAll(input.getMainAttributes());
        } else {
            main.putValue("Manifest-Version", "1.0");
            main.putValue("Created-By", "1.0 (Android SignApk)");
        }

        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] buffer = new byte[4096];
        int num;

        // We sort the input entries by name, and add them to the
        // output manifest in sorted order.  We expect that the output
        // map will be deterministic.

        TreeMap<String, ZioEntry> byName = new TreeMap<String, ZioEntry>();
        byName.putAll(entries);

        for (ZioEntry entry: byName.values()) {
            String name = entry.getName();
            if (!entry.isDirectory() && !stripPattern.matcher(name).matches()) {
                InputStream data = entry.getInputStream();
                while ((num = data.read(buffer)) > 0) {
                    md.update(buffer, 0, num);
                }

                Attributes attr = null;
                if (input != null) attr = input.getAttributes(name);
                attr = attr != null ? new Attributes(attr) : new Attributes();
                attr.putValue("SHA1-Digest", Base64.encode(md.digest()));
                output.getEntries().put(name, attr);
            }
        }

        return output;
    }

    /**
     * Add a copy of the public key to the archive; this should
     * exactly match one of the files in
     * /system/etc/security/otacerts.zip on the device.  (The same
     * cert can be extracted from the CERT.RSA file but this is much
     * easier to get at.)
     */
    private static void addOtacert(ZipOutput outputJar,
                                   byte[] publicKey,
                                   long timestamp,
                                   Manifest manifest)
        throws IOException, GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA1");

        ZioEntry je = new ZioEntry(OTACERT_NAME);
        je.setTime(timestamp);
        je.getOutputStream().write(publicKey);
        outputJar.write(je);
        md.update(publicKey);

        Attributes attr = new Attributes();
        attr.putValue("SHA1-Digest", Base64.encode(md.digest()));
        manifest.getEntries().put(OTACERT_NAME, attr);
    }


    /** Write a .SF file with a digest of the specified manifest. */
    private static byte[] writeSignatureFile(Manifest manifest, ByteArrayOutputStream out)
            throws IOException, GeneralSecurityException {
        Manifest sf = new Manifest();
        Attributes main = sf.getMainAttributes();
        main.putValue("Signature-Version", "1.0");
        main.putValue("Created-By", "1.0 (Android SignApk)");

        MessageDigest md = MessageDigest.getInstance("SHA1");
        PrintStream print = new PrintStream(
                new DigestOutputStream(new ByteArrayOutputStream(), md),
                true, "UTF-8");

        // Digest of the entire manifest
        manifest.write(print);
        print.flush();
        main.putValue("SHA1-Digest-Manifest", Base64.encode(md.digest()));

        Map<String, Attributes> entries = manifest.getEntries();
        for (Map.Entry<String, Attributes> entry : entries.entrySet()) {
            // Digest of the manifest stanza for this entry.
            print.print("Name: " + entry.getKey() + "\r\n");
            for (Map.Entry<Object, Object> att : entry.getValue().entrySet()) {
                print.print(att.getKey() + ": " + att.getValue() + "\r\n");
            }
            print.print("\r\n");
            print.flush();

            Attributes sfAttr = new Attributes();
            sfAttr.putValue("SHA1-Digest", Base64.encode(md.digest()));
            sf.getEntries().put(entry.getKey(), sfAttr);
        }

        sf.write(out);

        // A bug in the java.util.jar implementation of Android platforms
        // up to version 1.6 will cause a spurious IOException to be thrown
        // if the length of the signature file is a multiple of 1024 bytes.
        // As a workaround, add an extra CRLF in this case.
        if ((out.size() % 1024) == 0) {
            out.write('\r');
            out.write('\n');
        }
        return out.toByteArray();
    }

    /** Write a .RSA file with a digital signature. */
    private static void writeSignatureBlock(
            Signature signature, byte[] sbt, OutputStream out)
            throws IOException, GeneralSecurityException {
        out.write(sbt);
        out.write(signature.sign());
    }

    private static class WholeFileSignerOutputStream extends OutputStream {
        private boolean closing = false;
        private ByteArrayOutputStream footer = new ByteArrayOutputStream();
        private OutputStream out;
        private Signature sig;

        public WholeFileSignerOutputStream(OutputStream out, Signature sig) {
            this.out = out;
            this.sig = sig;
        }

        public void notifyClosing() {
            closing = true;
        }

        public void finish() throws IOException {
            closing = false;

            byte[] data = footer.toByteArray();
            if (data.length < 2)
                throw new IOException("Less than two bytes written to footer");
            write(data, 0, data.length - 2);
        }

        public byte[] getTail() {
            return footer.toByteArray();
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            // if the jar is about to close, save the footer that will be written
            if (closing) {
                footer.write(b, off, len);
            } else {
                try {
                    sig.update(b, off, len);
                } catch (GeneralSecurityException e) {
                    throw new IOException("SignatureException: " + e);
                }
                out.write(b, off, len);
            }
        }

        @Override
        public void write(int b) throws IOException {
            // if the jar is about to close, save the footer that will be written
            if (closing) {
                footer.write(b);
            } else {
                try {
                    sig.update((byte) b);
                } catch (GeneralSecurityException e) {
                    throw new IOException("SignatureException: " + e);
                }
                out.write(b);
            }
        }
    }

    private static void signWholeOutputFile(byte[] zipData,
                                            OutputStream outputStream,
                                            Signature signature,
                                            byte[] sbtbytes)
        throws IOException, GeneralSecurityException {

        // For a zip with no archive comment, the
        // end-of-central-directory record will be 22 bytes long, so
        // we expect to find the EOCD marker 22 bytes from the end.
        if (zipData[zipData.length-22] != 0x50 ||
            zipData[zipData.length-21] != 0x4b ||
            zipData[zipData.length-20] != 0x05 ||
            zipData[zipData.length-19] != 0x06) {
            throw new IllegalArgumentException("zip data already has an archive comment");
        }

        ByteArrayOutputStream temp = new ByteArrayOutputStream();

        // put a readable message and a null char at the start of the
        // archive comment, so that tools that display the comment
        // (hopefully) show something sensible.
        // TODO: anything more useful we can put in this message?
        byte[] message = "signed by SignApk".getBytes("UTF-8");
        temp.write(message);
        temp.write(0);
        writeSignatureBlock(signature, sbtbytes, temp);
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

    /**
     * Copy all the files in a manifest from input to output.  We set
     * the modification times in the output to a fixed time, so as to
     * reduce variation in the output file and make incremental OTAs
     * more efficient.
     */
    private static void copyFiles(Manifest manifest,
        ZipInput in, ZipOutput out, long timestamp) throws IOException  {
        Map<String, Attributes> entries = manifest.getEntries();
        ArrayList<String> names = new ArrayList<String>(entries.keySet());
        Collections.sort(names);
        Map<String, ZioEntry> input = in.getEntries();
        for (String name : names) {
            if (name.equals(OTACERT_NAME)) continue;
            ZioEntry inEntry = input.get(name);
            inEntry.setTime(timestamp);
            out.write(inEntry);
        }
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
        if (args.length != 2 && args.length != 3) {
            System.err.println("Usage: signapk [-w] " +
                    "input.jar output.jar");
            System.exit(2);
        }

        boolean signWholeFile = false;
        boolean align = true;
        int argstart = 0;
        if (args[0].equals("-w")) {
            signWholeFile = true;
            align = false;
            argstart = 1;
        }

        ZipInput inputJar = null;
        ZipOutput outputJar = null;
        FileOutputStream outputFile = null;

        try {

            // Set all ZIP file timestamps to Jan 1 2009 00:00:00.
            long timestamp = 1230768000000L;
            // The Java ZipEntry API we're using converts milliseconds since epoch into MS-DOS
            // timestamp using the current timezone. We thus adjust the milliseconds since epoch
            // value to end up with MS-DOS timestamp of Jan 1 2009 00:00:00.
            timestamp -= TimeZone.getDefault().getOffset(timestamp);

            byte[] pk8bytes = toByteArray(SignApk.class.getResourceAsStream("/keys/testkey.pk8"));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pk8bytes));
            inputJar = ZipInput.read(args[argstart+0], align);

            outputFile = new FileOutputStream(args[argstart+1]);
            Signature wfsig = null;
            WholeFileSignerOutputStream wfsos = null;
            if (signWholeFile) {
                wfsig = Signature.getInstance("SHA1withRSA");
                wfsig.initSign(privateKey);
            	wfsos = new WholeFileSignerOutputStream(outputFile, wfsig);
                outputJar = new ZipOutput(wfsos);
            } else {
                outputJar = new ZipOutput(outputFile);
            }

            ZioEntry je;

            Manifest manifest = addDigestsToManifest(inputJar);

            // otacert
            if (signWholeFile) {
                addOtacert(outputJar, toByteArray(SignApk.class.getResourceAsStream("/keys/testkey.x509.pem")), timestamp, manifest);
            }

            // MANIFEST.MF
            je = new ZioEntry(JarFile.MANIFEST_NAME);
            je.setTime(timestamp);
            manifest.write(je.getOutputStream());
            outputJar.write(je);

            // CERT.SF
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            je = new ZioEntry(CERT_SF_NAME);
            je.setTime(timestamp);
            byte[] sfBytes = writeSignatureFile(manifest, new ByteArrayOutputStream());
            je.getOutputStream().write(sfBytes);
            outputJar.write(je);
            signature.update(sfBytes);

            // CERT.RSA
            je = new ZioEntry(CERT_RSA_NAME);
            je.setTime(timestamp);
            byte[] sbtbytes = toByteArray(SignApk.class.getResourceAsStream("/keys/testkey.sbt"));
            writeSignatureBlock(signature, sbtbytes, je.getOutputStream());
            outputJar.write(je);

            // Everything else
            copyFiles(manifest, inputJar, outputJar, timestamp);

            if (signWholeFile) {
                wfsos.notifyClosing();
                outputJar.close();
                wfsos.finish();
            } else {
                outputJar.close();
            }
            outputJar = null;
            outputFile.flush();

            if (signWholeFile) {
                signWholeOutputFile(wfsos.getTail(), outputFile, wfsig, sbtbytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        } finally {
            try {
                if (inputJar != null) inputJar.close();
                if (outputFile != null) outputFile.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
