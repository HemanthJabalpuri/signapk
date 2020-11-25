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

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

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

    private static X509Certificate readPublicKey(File file)
            throws IOException, GeneralSecurityException {
        FileInputStream input = new FileInputStream(file);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(input);
        } finally {
            input.close();
        }
    }

    /**
     * Reads the password from stdin and returns it as a string.
     *
     * @param keyFile The file containing the private key.  Used to prompt the user.
     */
    private static String readPassword(File keyFile) {
        // TODO: use Console.readPassword() when it's available.
        System.out.print("Enter password for " + keyFile + " (password will not be hidden): ");
        System.out.flush();
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        try {
            return stdin.readLine();
        } catch (IOException ex) {
            return null;
        }
    }

    /**
     * Decrypt an encrypted PKCS#8 format private key.
     *
     * Based on ghstark's post on Aug 6, 2006 at
     * http://forums.sun.com/thread.jspa?threadID=758133&messageID=4330949
     *
     * @param encryptedPrivateKey The raw data of the private key
     * @param keyFile The file containing the private key
     */
    private static KeySpec decryptPrivateKey(byte[] encryptedPrivateKey, File keyFile)
            throws GeneralSecurityException {
        EncryptedPrivateKeyInfo epkInfo;
        try {
            epkInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKey);
        } catch (IOException ex) {
            // Probably not an encrypted key.
            return null;
        }

        char[] password = readPassword(keyFile).toCharArray();

        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());

        try {
            return epkInfo.getKeySpec(cipher);
        } catch (InvalidKeySpecException ex) {
            System.err.println("signapk: Password for " + keyFile + " may be bad.");
            throw ex;
        }
    }

    /** Read a PKCS#8 format private key. */
    private static PrivateKey readPrivateKey(File file)
            throws IOException, GeneralSecurityException {
        DataInputStream input = new DataInputStream(new FileInputStream(file));
        try {
            byte[] bytes = new byte[(int) file.length()];
            input.read(bytes);

            KeySpec spec = decryptPrivateKey(bytes, file);
            if (spec == null) {
                spec = new PKCS8EncodedKeySpec(bytes);
            }

            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (InvalidKeySpecException ex) {
                return KeyFactory.getInstance("DSA").generatePrivate(spec);
            }
        } finally {
            input.close();
        }
    }

    /** Add the SHA1 of every file to the manifest, creating it if necessary. */
    private static Manifest addDigestsToManifest(JarFile jar)
            throws IOException, GeneralSecurityException {
        Manifest input = jar.getManifest();
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

        TreeMap<String, JarEntry> byName = new TreeMap<String, JarEntry>();

        for (Enumeration<JarEntry> e = jar.entries(); e.hasMoreElements(); ) {
            JarEntry entry = e.nextElement();
            byName.put(entry.getName(), entry);
        }

        for (JarEntry entry: byName.values()) {
            String name = entry.getName();
            if (!entry.isDirectory() && !stripPattern.matcher(name).matches()) {
                InputStream data = jar.getInputStream(entry);
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
    private static void addOtacert(JarOutputStream outputJar,
                                   File publicKeyFile,
                                   long timestamp,
                                   Manifest manifest)
        throws IOException, GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA1");

        JarEntry je = new JarEntry(OTACERT_NAME);
        je.setTime(timestamp);
        outputJar.putNextEntry(je);
        FileInputStream input = new FileInputStream(publicKeyFile);
        byte[] b = new byte[4096];
        int read;
        while ((read = input.read(b)) != -1) {
            outputJar.write(b, 0, read);
            md.update(b, 0, read);
        }
        input.close();

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
            Signature signature, X509Certificate publicKey, OutputStream out)
            throws IOException, GeneralSecurityException {
        SignerInfo signerInfo = new SignerInfo(
                new X500Name(publicKey.getIssuerX500Principal().getName()),
                publicKey.getSerialNumber(),
                AlgorithmId.get("SHA1"),
                AlgorithmId.get("RSA"),
                signature.sign());

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[] { AlgorithmId.get("SHA1") },
                new ContentInfo(ContentInfo.DATA_OID, null),
                new X509Certificate[] { publicKey },
                new SignerInfo[] { signerInfo });

        pkcs7.encodeSignedData(out);
    }

    private static void signWholeOutputFile(byte[] zipData,
                                            OutputStream outputStream,
                                            X509Certificate publicKey,
                                            PrivateKey privateKey)
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

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(zipData, 0, zipData.length-2);

        ByteArrayOutputStream temp = new ByteArrayOutputStream();

        // put a readable message and a null char at the start of the
        // archive comment, so that tools that display the comment
        // (hopefully) show something sensible.
        // TODO: anything more useful we can put in this message?
        byte[] message = "signed by SignApk".getBytes("UTF-8");
        temp.write(message);
        temp.write(0);
        writeSignatureBlock(signature, publicKey, temp);
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

        outputStream.write(zipData, 0, zipData.length-2);
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
        JarFile in, JarOutputStream out, long timestamp, int defaultAlignment) throws IOException {
        byte[] buffer = new byte[4096];
        int num;

        Map<String, Attributes> entries = manifest.getEntries();
        ArrayList<String> names = new ArrayList<String>(entries.keySet());
        Collections.sort(names);

        boolean firstEntry = true;
        long offset = 0L;

        // We do the copy in two passes -- first copying all the
        // entries that are STORED, then copying all the entries that
        // have any other compression flag (which in practice means
        // DEFLATED).  This groups all the stored entries together at
        // the start of the file and makes it easier to do alignment
        // on them (since only stored entries are aligned).

        for (String name : names) {
            JarEntry inEntry = in.getJarEntry(name);
            JarEntry outEntry = null;
            if (inEntry.getMethod() != JarEntry.STORED) continue;
            // Preserve the STORED method of the input entry.
            outEntry = new JarEntry(inEntry);
            outEntry.setTime(timestamp);
            // Discard comment and extra fields of this entry to
            // simplify alignment logic below and for consistency with
            // how compressed entries are handled later.
            outEntry.setComment(null);
            outEntry.setExtra(null);

            // 'offset' is the offset into the file at which we expect
            // the file data to begin.  This is the value we need to
            // make a multiple of 'alignement'.
            offset += 30 + outEntry.getName().length();
            if (firstEntry) {
                // The first entry in a jar file has an extra field of
                // four bytes that you can't get rid of; any extra
                // data you specify in the JarEntry is appended to
                // these forced four bytes.  This is JAR_MAGIC in
                // JarOutputStream; the bytes are 0xfeca0000.
                offset += 4;
                firstEntry = false;
            }
            // Align .so contents to memory page boundary to enable memory-mapped execution.
            int alignment = name.endsWith(".so") ? 4096 : defaultAlignment;
            if (alignment > 0 && (offset % alignment != 0)) {
                // Set the "extra data" of the entry to between 1 and
                // alignment-1 bytes, to make the file data begin at
                // an aligned offset.
                int needed = alignment - (int)(offset % alignment);
                outEntry.setExtra(new byte[needed]);
                offset += needed;
            }

            out.putNextEntry(outEntry);

            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
                offset += num;
            }
            out.flush();
        }

        // Copy all the non-STORED entries.  We don't attempt to
        // maintain the 'offset' variable past this point; we don't do
        // alignment on these entries.

        for (String name : names) {
            JarEntry inEntry = in.getJarEntry(name);
            JarEntry outEntry = null;
            if (inEntry.getMethod() == JarEntry.STORED) continue;
            // Create a new entry so that the compressed len is recomputed.
            outEntry = new JarEntry(name);
            outEntry.setTime(timestamp);
            out.putNextEntry(outEntry);

            InputStream data = in.getInputStream(inEntry);
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
            }
            out.flush();
        }
    }

    public static void main(String[] args) {
        if (args.length != 4 && args.length != 5) {
            System.err.println("Usage: signapk [-w] " +
                    "publickey.x509[.pem] privatekey.pk8 " +
                    "input.jar output.jar");
            System.exit(2);
        }

        boolean signWholeFile = false;
        int alignment = 4;
        int argstart = 0;
        if (args[0].equals("-w")) {
            signWholeFile = true;
            alignment = 0;
            argstart = 1;
        }

        JarFile inputJar = null;
        JarOutputStream outputJar = null;
        FileOutputStream outputFile = null;

        try {
            File publicKeyFile = new File(args[argstart+0]);
            X509Certificate publicKey = readPublicKey(publicKeyFile);

            // Set all ZIP file timestamps to Jan 1 2009 00:00:00.
            long timestamp = 1230768000000L;
            // The Java ZipEntry API we're using converts milliseconds since epoch into MS-DOS
            // timestamp using the current timezone. We thus adjust the milliseconds since epoch
            // value to end up with MS-DOS timestamp of Jan 1 2009 00:00:00.
            timestamp -= TimeZone.getDefault().getOffset(timestamp);

            PrivateKey privateKey = readPrivateKey(new File(args[argstart+1]));
            inputJar = new JarFile(new File(args[argstart+2]), false);  // Don't verify.

            OutputStream outputStream = null;
            if (signWholeFile) {
                outputStream = new ByteArrayOutputStream();
            } else {
                outputStream = new FileOutputStream(args[argstart+3]);
            }
            outputJar = new JarOutputStream(outputStream);

            // For signing .apks, use the maximum compression to make
            // them as small as possible (since they live forever on
            // the system partition).  For OTA packages, use the
            // default compression level, which is much much faster
            // and produces output that is only a tiny bit larger
            // (~0.1% on full OTA packages I tested).
            if (!signWholeFile) {
                outputJar.setLevel(9);
            }

            JarEntry je;

            Manifest manifest = addDigestsToManifest(inputJar);

            // Everything else
            copyFiles(manifest, inputJar, outputJar, timestamp, alignment);

            // otacert
            if (signWholeFile) {
                addOtacert(outputJar, publicKeyFile, timestamp, manifest);
            }

            // MANIFEST.MF
            je = new JarEntry(JarFile.MANIFEST_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            manifest.write(outputJar);

            // CERT.SF
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey);
            je = new JarEntry(CERT_SF_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            byte[] sfBytes = writeSignatureFile(manifest, new ByteArrayOutputStream());
            outputJar.write(sfBytes);
            signature.update(sfBytes);

            // CERT.RSA
            je = new JarEntry(CERT_RSA_NAME);
            je.setTime(timestamp);
            outputJar.putNextEntry(je);
            writeSignatureBlock(signature, publicKey, outputJar);

            outputJar.close();
            outputJar = null;
            outputStream.flush();

            if (signWholeFile) {
                outputFile = new FileOutputStream(args[argstart+3]);
                signWholeOutputFile(((ByteArrayOutputStream)outputStream).toByteArray(),
                                    outputFile, publicKey, privateKey);
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
