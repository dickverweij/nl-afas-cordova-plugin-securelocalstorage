Secure localStorage for Cordova
==========================
This plugin will store local data encrypted using IOS keychain or Android keystore.
ANDROID: The local storage will have an expiration date of 3 years. If the encrypted file is invalid,
the localstorage will clear itself.

WARNING: This is no protection for hackers who have physical/root access to your phone. 

Goal: Protect against reading/writing the contents stored in the the SecureLocalStorage by other apps.
Use it to store temporary sensitive data which will survice an app exit/shutdown. 

Requirements
-------------
- Android 4.3 or higher / iOS 6 or higher
- Cordova 3.0 or higher

    Installation
-------------
    cordova plugin add https://github.com/dickverweij/nl-afas-cordova-plugin-secureLocalStorage

Usage
------
    
    window.secureLocalStorage.setItem("key" , "value");

    vwindow.secureLocalStorage.getItem("key").then(function (value){...})

    window.secureLocalStorage.removeItem("key");

    window.secureLocalStorage.clear();




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
