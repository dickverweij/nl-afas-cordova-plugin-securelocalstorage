cordova.define("nl.afas.cordova.plugin.secureLocalStorage.SecureLocalStorage", function (require, exports, module) { /*jslint browser: true, devel: true, node: true, sloppy: true, plusplus: true*/
    /*global require, cordova */
    /*
    The MIT License (MIT)
    
    Copyright (c) 2015 Dick Verweij, dickydick1969@hotmail.com, AFAS Software  - d.verweij@afas.nl
    
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
    var exec = require('cordova/exec');

    function SecureLocalStorage() { }

    SecureLocalStorage.prototype.getItem = function (key) {
        return exec(resolve, reject, 'SecureLocalStorage', 'getItem', [key]);        
    };

    SecureLocalStorage.prototype.setItem = function (key, value) {        
        exec(resolve, reject, 'SecureLocalStorage', 'setItem', [key, value]);
        
    };

    SecureLocalStorage.prototype.removeItem = function (key) {        
        exec(resolve, reject, 'SecureLocalStorage', 'removeItem', [key]);        
    };

    SecureLocalStorage.prototype.clear = function () {
        exec(resolve, reject, 'SecureLocalStorage', 'clear', []);        
    };


    window.SecureLocalStorage = new SecureLocalStorage();

});
