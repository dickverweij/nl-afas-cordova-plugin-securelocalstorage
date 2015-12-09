/*
The MIT License (MIT)

Copyright (c) 2015 Dick Verweij dickydick1969@hotmail.com, d.verweij@afas.nl

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package nl.afas.cordova.plugin.secureLocalStorage;

import java.io.File;

import org.json.JSONArray;

import android.annotation.TargetApi;
import android.app.Activity;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;

import android.os.Build;
import android.security.KeyPairGeneratorSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;


import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import org.json.JSONException;

import java.util.concurrent.locks.ReentrantLock;

public class SecureLocalStorage extends CordovaPlugin {

    public class SecureLocalStorageException extends Exception{
        public SecureLocalStorageException(String message){
            super(message);
        }
        public SecureLocalStorageException(String message,Exception ex){
            super(message,ex);
        }
    }

    private static final String SECURELOCALSTORAGEFILE = "secureLocalStorage.dat";
    private static final String SECURELOCALSTORAGEALIAS = "SECURELOCALSTORAGEPPKEYALIAS";
    private final ReentrantLock lock = new ReentrantLock();
    private Activity _activity;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        _activity = cordova.getActivity();
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

        boolean foundMethod = false;
        try {
            if (Build.VERSION.SDK_INT < 18) {
                throw new SecureLocalStorageException("Invalid API Level (must be >= 18");
            }

            KeyStore keyStore = initKeyStore();

            // init the storage with an empty hashtable if needed
            File file = _activity.getBaseContext().getFileStreamPath(SECURELOCALSTORAGEFILE);
            HashMap<String, String> hashMap = new HashMap<String, String>();


            // lock the access
            lock.lock();
            try {

                // clear just deletes the storage file
                if (action.equals("clear")) {
                    foundMethod = true;
                    if (file.exists()) {
                        if (!file.delete()) {
                            throw new SecureLocalStorageException("Could not delete storage file");
                        }
                    }
                } else {

                    // initialize for reading later
                    if (!file.exists()) {
                        writeAndEncryptStorage(keyStore, hashMap);
                    }

                    // read current storage hashmap
                    hashMap = readAndDecryptStorage(keyStore);

                    String key = args.getString(0);

                    if (key == null || key.length() == 0) {
                        throw new SecureLocalStorageException("Key is empty or null");
                    }
                    // handle the methods. Note: getItem uses callback
                    if (action.equals("getItem")) {
                        foundMethod = true;

                        if (hashMap.containsKey(key)) {
                            if (callbackContext != null) {
                                callbackContext.success(hashMap.get(key));
                            }
                        } else {
                            callbackContext.success((String) null);
                        }
                    } else if (action.equals("setItem")) {
                        foundMethod = true;

                        String value = args.getString(1);
                        if (value == null) {
                            throw new SecureLocalStorageException("Value is null");
                        }

                        hashMap.put(key, value);
                        writeAndEncryptStorage(keyStore, hashMap);


                    } else if (action.equals("removeItem")) {
                        foundMethod = true;

                        hashMap.remove(key);
                        writeAndEncryptStorage(keyStore, hashMap);
                    }
                }
            } finally {
                lock.unlock();
            }
        } catch (SecureLocalStorageException ex) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            ex.printStackTrace(pw);
            pw.close();
            throw new JSONException(sw.toString());
        }

        return foundMethod;
    }

    @TargetApi(18)
    private KeyStore initKeyStore() throws SecureLocalStorageException {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (!keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.MINUTE, 1);

                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(_activity)
                        .setAlias(SECURELOCALSTORAGEALIAS)
                        .setSubject(new X500Principal(String.format("CN=%s, O=%s", "SecureLocalStorage", _activity.getBaseContext().getPackageName())))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                generator.generateKeyPair();
            }
            return keyStore;
        }
        catch (IOException e){
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        } catch (CertificateException e) {
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        } catch (NoSuchAlgorithmException e) {
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        } catch (KeyStoreException e) {
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        } catch (NoSuchProviderException e) {
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        }
    }

    @SuppressWarnings("unchecked")
    private HashMap<String, String> readAndDecryptStorage(KeyStore keyStore) throws SecureLocalStorageException {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);

            FileInputStream fis = _activity.openFileInput(SECURELOCALSTORAGEFILE);
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    fis, output);
            ArrayList<Byte> values = new ArrayList<Byte>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            return (HashMap<String, String>) ois.readObject();
        }
        catch(IOException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (NoSuchPaddingException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (InvalidKeyException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (NoSuchAlgorithmException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (KeyStoreException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (NoSuchProviderException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (UnrecoverableEntryException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        } catch (ClassNotFoundException e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        }
    }

    private void writeAndEncryptStorage(KeyStore keyStore, HashMap<String, String> table) throws SecureLocalStorageException {

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(table);
            oos.close();

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            FileOutputStream fos = _activity.openFileOutput(SECURELOCALSTORAGEFILE, Context.MODE_PRIVATE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    fos, input);
            cipherOutputStream.write(bos.toByteArray());
            cipherOutputStream.close();

            bos.close();
        }
        catch (IOException e){
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (NoSuchPaddingException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (InvalidKeyException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (NoSuchAlgorithmException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (KeyStoreException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (NoSuchProviderException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        } catch (UnrecoverableEntryException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        }
    }
}

