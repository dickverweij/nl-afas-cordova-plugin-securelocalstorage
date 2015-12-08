/*
The MIT License (MIT)

Copyright (c) 2013 pwlin - pwlin05@gmail.com

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
package io.github.pwlin.cordova.plugins.fileopener2;

import java.io.File;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.widget.Toast;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
//import android.util.Log;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CordovaResourceApi;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;


public class SecureLocalStorage extends CordovaPlugin {

	private final String alias = "AFASPOCKETPPKEY";
	
	@Override
	public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
		try{
			KeyStore keyStore = initKeyStore();

			// initial keystore
			File file = getBaseContext().getFileStreamPath("secureLocalStorage.dat");
			Hashtable<String,String> hashtable = new Hashtable<String,String>();
			if (!file.exists()) {
				writeAndCryptHashtable(keyStore, hashtable);
			}
        
			if (action.equals("clear")){
				writeAndCryptHashtable(keyStore, hashtable);
				return true;
			}

			String key = args.getString(0);
			hastable = readAndDecryptHashtable(keyStore);

			if (action.equals("getItem")){
				if (hashtable.containsKey(key))
				{
					callbackContext.success(hashtable.get(key));
				}
				else
				{
					callbackContext.failure();
				}

				return true;	
			} 
			else if (action.equals("setItem")){
			
				hashtable.put(key, args.getString(1));
				writeAndCryptHashtable(keyStore, hashtable);

				return true;	
			} 

		}
		catch (Exception ex){
			callbackContext.failure(ex.getMessage());
			return true;	
		}

		return false;
	}

	private KeyStore initKeyStore() throws IOException,CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        if (!keyStore.containsAlias(alias)) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
                    .setAlias(alias)
                    .setSubject(new X500Principal(String.format("CN=%s, O=%s", alias, getBaseContext().getPackageName())))
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

	private Hashtable<String, String> readAndDecryptHashtable(KeyStore keyStore) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException, ClassNotFoundException {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);

        FileInputStream fis = openFileInput("secureLocalStorage.dat");
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
            bytes[i] = values.get(i).byteValue();
        }

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        return (Hashtable<String,String>) ois.readObject();
    }

    private void writeAndCryptHashtable(KeyStore keyStore, Hashtable<String,String> table) throws IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(table);
        oos.close();

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

        Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL");
        input.init(Cipher.ENCRYPT_MODE, publicKey);

        FileOutputStream fos = openFileOutput("secureLocalStorage.dat", Context.MODE_PRIVATE);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(
                fos, input);
        cipherOutputStream.write(bos.toByteArray());
        cipherOutputStream.close();

        bos.close();
    }

}
