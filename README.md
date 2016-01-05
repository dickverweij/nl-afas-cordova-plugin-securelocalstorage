Secure localStorage for Cordova
==========================
This plugin will store local data encrypted using the IOS keychain or the Android keystore.

ANDROID: The local storage will have an expiration date of 3 years if left untouched. If the encrypted file is invalid,
the localstorage will clear itself. A clear() will also re-initialize the certificate.

WARNING: This is no protection for hackers who have physical/root access to your phone. 

Use it to store temporary sensitive data which has to survive an app exit/shutdown. 

Requirements
-------------
- Android 4.3 or higher / iOS 6 or higher
- Cordova 3.0 or higher

    Installation
-------------
    cordova plugin add https://github.com/dickverweij/nl-afas-cordova-plugin-secureLocalStorage

Usage
------
    
    cordova.SecureLocalStorage.setItem("key" , "value");

    cordova.SecureLocalStorage.getItem("key").then(function (value){...})

    cordova.SecureLocalStorage.removeItem("key");

    cordova.SecureLocalStorage.clear();




LICENSE
--------
The MIT License (MIT)

Copyright (c) 2015 dickydick1969@hotmail.com Dick Verweij AFAS Software BV - d.verweij@afas.nl


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
