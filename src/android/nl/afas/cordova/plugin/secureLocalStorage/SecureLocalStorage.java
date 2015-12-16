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
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import android.content.Context;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.io.PrintWriter;
import java.io.RandomAccessFile;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;


import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.json.JSONException;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
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

    // encrypted local storage
    private static final String SECURELOCALSTORAGEFILE = "secureLocalStorage.sdat";
    // encrypted key
    private static final String SECURELOCALSTORAGEKEY =  "secureLocalStorage.kdat";
    private static final String SECURELOCALSTORAGEALIAS = "SECURELOCALSTORAGEPPKEYALIAS";

    private final ReentrantLock lock = new ReentrantLock();
    private CordovaInterface _cordova;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        _cordova = cordova;
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {

        // start thread
        try {
            return _cordova.getThreadPool().submit(new Callable<Boolean>() {
                @Override
                public Boolean call() throws JSONException {
                    boolean foundMethod = false;
                    try {
                        if (Build.VERSION.SDK_INT < 18) {
                            throw new SecureLocalStorageException("Invalid API Level (must be >= 18");
                        }

                        File file = _cordova.getActivity().getBaseContext().getFileStreamPath(SECURELOCALSTORAGEFILE);
                        HashMap<String, String> hashMap = new HashMap<String, String>();

                        // lock the access
                        lock.lock();
                        try {
							KeyStore keyStore = initKeyStore();

                            // clear just deletes the storage file
                            if (action.equals("clear")) {
                                foundMethod = true;
                                clear(file, keyStore);

                            } else {

                                // clear localStorage if invalid
                                if (action.equals("clearIfInvalid")) {
                                    foundMethod = true;                                   
                                    try {
                                        checkValidity();
                                        if (file.exists()) {
                                            readAndDecryptStorage(keyStore);
                                        }
                                    } catch (SecureLocalStorageException ex) {
                                        clear(file, keyStore);                                       
                                    }
                                } else {                                   
                                    // initialize for reading later
                                    if (!file.exists()) {
                                        // generate key and store in keyStore
                                        generateKey(keyStore);

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
                                                String value = hashMap.get(key);

                                                callbackContext.success(value);
                                            }
                                        } else {
                                            // return null when not found
                                            callbackContext.success((String) null);
                                        }
                                    } else if (action.equals("setItem")) {
                                        foundMethod = true;

                                        String value = args.getString(1);
                                        if (value == null) {
                                            throw new SecureLocalStorageException("Value is null");
                                        }

                                        hashMap.put(key, value);

                                        // store back
                                        writeAndEncryptStorage(keyStore, hashMap);

                                    } else if (action.equals("removeItem")) {
                                        foundMethod = true;

                                        hashMap.remove(key);

                                        // store back
                                        writeAndEncryptStorage(keyStore, hashMap);
                                    }
                                }
                            }

                        } finally {
                            lock.unlock();
                        }

                    } catch (SecureLocalStorageException ex) {

                        ex.printStackTrace();

                        StringWriter sw = new StringWriter();
                        PrintWriter pw = new PrintWriter(sw);
                        ex.printStackTrace(pw);
                        pw.close();

                        throw new JSONException(sw.toString());
                    }

                    return foundMethod;
                }
            }).get();
        } catch (InterruptedException e) {
        } catch (ExecutionException e) {
        }

        return false;
    }

    @TargetApi(18)
    private KeyStore initKeyStore() throws SecureLocalStorageException {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            if (!keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {

                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 3);

                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(_cordova.getActivity())
                        .setAlias(SECURELOCALSTORAGEALIAS)
                        .setSubject(new X500Principal(String.format("CN=%s, O=%s", "SecureLocalStorage", _cordova.getActivity().getBaseContext().getPackageName())))
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

    private void clear(File file, KeyStrore keyStore) throws SecureLocalStorageException {
        if (file.exists()) {
            if (!file.delete()) {
                throw new SecureLocalStorageException("Could not delete storage file");
            }
        }
		try {
			if (keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
                keyStore.deleteEntry(SECURELOCALSTORAGEALIAS);
			}
        } catch (KeyStoreException e) {
		     throw new SecureLocalStorageException("Could not delete keystore alias");
        }
    }

    private void checkValidity() throws SecureLocalStorageException {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);


            if (keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
                Certificate c = keyStore.getCertificate(SECURELOCALSTORAGEALIAS);
                if (c.getType().equals("X.509")) {
                    ((X509Certificate) c).checkValidity();
                }
            }
        } catch (CertificateException e) {
        } catch (NoSuchAlgorithmException e) {
        } catch (KeyStoreException e) {
        } catch (IOException e) {
        }
    }

    private SecretKey getSecretKey(KeyStore keyStore) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException, ClassNotFoundException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);

        FileInputStream fis = _cordova.getActivity().openFileInput(SECURELOCALSTORAGEKEY);
        ArrayList<Byte> values = new ArrayList<Byte>();
        try {
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    fis, output);
            try {

                int nextByte;
                while ((nextByte = cipherInputStream.read()) != -1) {
                    values.add((byte) nextByte);
                }
            }
            finally {
                cipherInputStream.close();
            }
        }
        finally {
            fis.close();
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i);
        }

        SecretKey key;
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        try {
            key = (SecretKey) ois.readObject();
        }
        finally {
            ois.close();
        }
        return key;
    }

    private void generateKey(KeyStore keyStore) throws SecureLocalStorageException {

        try {
            SecretKey key = KeyGenerator.getInstance("DES").generateKey();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                try {
                    oos.writeObject(key);
                } finally {
                    oos.close();
                }
            } finally {
                bos.close();
            }

            // store key encrypted with keystore key pair
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            FileOutputStream fos = _cordova.getActivity().openFileOutput(SECURELOCALSTORAGEKEY, Context.MODE_PRIVATE);
            try {
                CipherOutputStream cipherOutputStream = new CipherOutputStream(
                        fos, input);
                try {
                    cipherOutputStream.write(bos.toByteArray());
                } finally {
                    cipherOutputStream.close();
                }
            } finally {
                fos.close();
            }

        } catch (IOException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (NoSuchPaddingException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (InvalidKeyException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (KeyStoreException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (NoSuchProviderException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        } catch (UnrecoverableEntryException e) {
            throw new SecureLocalStorageException("Error generating key", e);
        }
    }


    @SuppressWarnings("unchecked")
    private HashMap<String, String> readAndDecryptStorage(KeyStore keyStore) throws SecureLocalStorageException {
        try {
            // obtain encrypted key
            SecretKey key = getSecretKey(keyStore);

            FileInputStream fis = _cordova.getActivity().openFileInput(SECURELOCALSTORAGEFILE);
            ArrayList<Byte> values = new ArrayList<Byte>();
            try {

                Cipher output = Cipher.getInstance("DES");
                output.init(Cipher.DECRYPT_MODE, key);

                CipherInputStream cipherInputStream = new CipherInputStream(
                        fis, output);
                try {

                    int nextByte;
                    while ((nextByte = cipherInputStream.read()) != -1) {
                        values.add((byte) nextByte);
                    }
                }
                finally {
                    cipherInputStream.close();
                }
            }
            finally {
                fis.close();
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            HashMap<String,String> hashMap;
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            try {
                hashMap = (HashMap<String,String>) ois.readObject();
            }
            finally {
                ois.close();
            }
            return hashMap;
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

    private void writeAndEncryptStorage(KeyStore keyStore, HashMap<String, String> hashMap) throws SecureLocalStorageException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try {
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                try {
                    oos.writeObject(hashMap);
                } finally {
                    oos.close();
                }
            } finally {
                bos.close();
            }

            SecretKey key = getSecretKey(keyStore);

            Cipher input = Cipher.getInstance("DES");
            input.init(Cipher.ENCRYPT_MODE, key);

            // encrypt the hashmap
            FileOutputStream fos = _cordova.getActivity().openFileOutput(SECURELOCALSTORAGEFILE, Context.MODE_PRIVATE);
            try {
                CipherOutputStream cipherOutputStream = new CipherOutputStream(
                        fos, input);
                try {
                    cipherOutputStream.write(bos.toByteArray());
                } finally {
                    cipherOutputStream.close();
                }
            } finally {
                fos.close();
            }

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
        } catch (ClassNotFoundException e) {
            throw new SecureLocalStorageException("Error encrypting storage",e);
        }
    }
}


























