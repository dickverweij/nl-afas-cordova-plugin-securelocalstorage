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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;


import org.apache.cordova.PluginResult;
import org.json.JSONArray;

import android.annotation.TargetApi;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import android.content.Context;

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

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;


import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.json.JSONException;

import java.util.concurrent.locks.ReentrantLock;

public class SecureLocalStorage extends CordovaPlugin {

    public enum ActionId {
        ACTION_NONE,
        ACTION_CLEARIFINVALID,
        ACTION_CLEAR,
        ACTION_GETITEM,
        ACTION_SETITEM,
        ACTION_REMOVEITEM
    }

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
    private static SecretKey _key = null;

    private CordovaInterface _cordova;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        _cordova = cordova;
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {

        final ActionId actionId = getActionId(action);
        if (actionId == ActionId.ACTION_NONE) {
            return false;
        }

        PluginResult pluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        pluginResult.setKeepCallback(true);
        callbackContext.sendPluginResult(pluginResult);

        // start thread
        _cordova.getThreadPool().execute(new Runnable() {
            @Override
            public void run() {

                try {
                    handleAction(actionId, args, callbackContext);
                } catch (SecureLocalStorageException ex) {
                    handleException(ex, callbackContext);
                } catch (JSONException ex) {
                    handleException(ex, callbackContext);
                }
            }
        });

        return true;
    }

    private void handleException(Exception ex, CallbackContext callbackContext) {

        ex.printStackTrace();
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        ex.printStackTrace(pw);
        pw.close();

        PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR,pw.toString());
        pluginResult.setKeepCallback(false);
        callbackContext.sendPluginResult(pluginResult);
    }

    private void handleAction(ActionId actionId, JSONArray args, CallbackContext callbackContext) throws SecureLocalStorageException, JSONException {
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
            if (actionId == ActionId.ACTION_CLEAR) {
                clear(file, keyStore);
				try {
                  keyStore = initKeyStore();
                  generateKey(keyStore);                
				}
				catch(SecureLocalStorageException ex2) {

				}
                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
                pluginResult.setKeepCallback(false);
                callbackContext.sendPluginResult(pluginResult);
            } else {

                // clear localStorage if invalid
                if (actionId == ActionId.ACTION_CLEARIFINVALID) {

                    try {
                        checkValidity();
                        
                        if (file.exists()) {
                        
                            // save hashmap for re-initializing certificate
                            hashMap = readAndDecryptStorage(keyStore);
							
							// only clear file if untouched for 10 days
                            if ((new Date().getTime() - file.lastModified()) > (10 * 24 * 60 * 60 * 1000)) {
                              
                              clear(file, keyStore);
                              
                              keyStore = initKeyStore();
                              
                              generateKey(keyStore);
                              
                              writeAndEncryptStorage(keyStore, hashMap);
                              
                            }
                        }
                    } catch (SecureLocalStorageException ex) {
                        clear(file, keyStore);
                        try {
                          keyStore = initKeyStore();
                          generateKey(keyStore);                          
                        }
                        catch(SecureLocalStorageException ex2) {

                        }

                    }
                    PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
                    pluginResult.setKeepCallback(false);
                    callbackContext.sendPluginResult(pluginResult);
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
                    if (actionId == ActionId.ACTION_GETITEM) {


                        if (hashMap.containsKey(key)) {
                            if (callbackContext != null) {
                                String value = hashMap.get(key);

                                PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, value);
                                pluginResult.setKeepCallback(false);
                                callbackContext.sendPluginResult(pluginResult);
                            }
                        } else {
                            // return null when not found
                            PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, (String)null);
                            pluginResult.setKeepCallback(false);
                            callbackContext.sendPluginResult(pluginResult);
                        }
                    } else if (actionId == ActionId.ACTION_SETITEM) {

                        String value = args.getString(1);
                        if (value == null) {
                            throw new SecureLocalStorageException("Value is null");
                        }

                        hashMap.put(key, value);

                        // store back
                        writeAndEncryptStorage(keyStore, hashMap);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
                        pluginResult.setKeepCallback(false);
                        callbackContext.sendPluginResult(pluginResult);

                    } else if (actionId == ActionId.ACTION_REMOVEITEM) {

                        hashMap.remove(key);

                        // store back
                        writeAndEncryptStorage(keyStore, hashMap);

                        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
                        pluginResult.setKeepCallback(false);
                        callbackContext.sendPluginResult(pluginResult);
                    }
                }
            }

        } finally {
            lock.unlock();
        }
    }

    private ActionId getActionId(final String action)
    {
        if (action.equals("clear")){
            return ActionId.ACTION_CLEAR;
        }
        if (action.equals("getItem")){
            return ActionId.ACTION_GETITEM;
        }
        if (action.equals("setItem")){
            return ActionId.ACTION_SETITEM;
        }
        if (action.equals("removeItem")){
            return ActionId.ACTION_REMOVEITEM;
        }
        if (action.equals("clearIfInvalid")){
            return ActionId.ACTION_CLEARIFINVALID;
        }
        return ActionId.ACTION_NONE;
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
        catch (Exception e){
            throw new SecureLocalStorageException("Could not initialize keyStore", e);
        }
    }

    private void clear(File file, KeyStore keyStore) throws SecureLocalStorageException {
        if (file.exists()) {
            if (!file.delete()) {
                throw new SecureLocalStorageException("Could not delete storage file");
            }
        }
		try {
			if (keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
                keyStore.deleteEntry(SECURELOCALSTORAGEALIAS);
			}
        } catch (Exception e) {
		     throw new SecureLocalStorageException(e.getMessage(), e);
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
        } catch (Exception e) {
            throw new SecureLocalStorageException(e.getMessage(), e);
        }
    }

    private SecretKey getSecretKey(KeyStore keyStore) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException, ClassNotFoundException {

        if (_key != null) {
          return _key;
        }
      
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);

        
        SecretKey key;

        FileInputStream fis = _cordova.getActivity().openFileInput(SECURELOCALSTORAGEKEY);
        try {

            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

            
            CipherInputStream cipherInputStream = new CipherInputStream(
                    fis, output);
            try {

              ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(cipherInputStream));

              key = (SecretKey) ois.readObject();

            }
            finally {
                cipherInputStream.close();
            }
        }
        finally {
            fis.close();
        }
        
        // store key for the lifetime for the app
        _key = key;
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

            Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            input.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

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

        } catch (Exception e) {
            throw new SecureLocalStorageException("Error generating key", e);
        }
    }


    @SuppressWarnings("unchecked")
    private HashMap<String, String> readAndDecryptStorage(KeyStore keyStore) throws SecureLocalStorageException {
        try {
          
            // obtain encrypted key
            SecretKey key = getSecretKey(keyStore);
            File f = new File(SECURELOCALSTORAGEFILE);
            

            FileInputStream fis = _cordova.getActivity().openFileInput(SECURELOCALSTORAGEFILE);
            HashMap<String, String> hashMap;
            try {

              Cipher output = Cipher.getInstance("DES");
              output.init(Cipher.DECRYPT_MODE, key);

              CipherInputStream cipherInputStream = new CipherInputStream(
                fis, output);

              try {
                ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(cipherInputStream));
                hashMap = (HashMap<String, String>) ois.readObject();
              }
              finally {
                cipherInputStream.close();
              }
            }
            finally {
              fis.close();
            }

            
            return hashMap;
        }
        catch(Exception e) {
            throw new SecureLocalStorageException("Error decrypting storage",e);
        }
    }

    private void writeAndEncryptStorage(KeyStore keyStore, HashMap<String, String> hashMap) throws SecureLocalStorageException {
        try {
            
            SecretKey key = getSecretKey(keyStore);

            Cipher input = Cipher.getInstance("DES");
            
            input.init(Cipher.ENCRYPT_MODE, key);

            // encrypt the hashmap
            FileOutputStream fos = _cordova.getActivity().openFileOutput(SECURELOCALSTORAGEFILE, Context.MODE_PRIVATE);
            try {
                CipherOutputStream cipherOutputStream = new CipherOutputStream(
                        fos, input);
                try {
                    ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(cipherOutputStream));

                    try {
                      oos.writeObject(hashMap);

                    } finally {
                      oos.close();
                    }
                } finally {
                    cipherOutputStream.close();
                }
            } finally {
                fos.close();
            }
            
        }
        catch (Exception e){
            throw new SecureLocalStorageException("Error encrypting storage",e);
        }

      
    }
}


























