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
#import "SecureLocalStorage.h"
#import <Cordova/CDV.h>

#import "KeychainItemWrapper.h"
#import <QuartzCore/QuartzCore.h>
#import <MobileCoreServices/MobileCoreServices.h>

@implementation SecureLocalStorage

- (void) writeToSecureStorage:(NSMutableDictionary*)dict{

    KeychainItemWrapper * keychain = [[KeychainItemWrapper alloc] initWithIdentifier:@"nl.afas.cordova.plugin.secureLocalStorage" accessGroup:nil];
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:&error];
    NSString *jsonString = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding]; 

    [keychain setObject:jsonString forKey:(__bridge id)(kSecValueData)];

}

- (NSMutableDictionary *) readFromSecureStorage {

    NSMutableDictionary * dict = nil;
    KeychainItemWrapper * keychain = [[KeychainItemWrapper alloc] initWithIdentifier:@"nl.afas.cordova.plugin.secureLocalStorage" accessGroup:nil];    
    NSError *error;
    @try{
        NSData *json = [keychain objectForKey:(__bridge id)(kSecValueData)];

        if (json != nil) {
            dict = [NSJSONSerialization JSONObjectWithData:json options: NSJSONReadingMutableContainers error:&error];
            if (error) {
                NSLog(@"%@", error);
            }
        }
    }
    @catch(NSException * exception)
    {
        NSLog(@"Exception: %@", exception);
    }

    return dict;
}

- (void) getItem: (CDVInvokedUrlCommand*)command {
	[self.commandDelegate runInBackground:^{
		@synchronized(self) {
			NSMutableDictionary * dict = [self readFromSecureStorage];
			CDVPluginResult * pluginResult;
			NSString * result = nil;

			if (dict != nil) {
				result =[dict valueForKey:command.arguments[0]];
			}

			pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:result];
			[self.commandDelegate sendPluginResult:pluginResult callbackId: command.callbackId];
		}
	}];
}

- (void) setItem: (CDVInvokedUrlCommand*)command {
	[self.commandDelegate runInBackground:^{
		@synchronized(self) {
			NSMutableDictionary * dict = [self readFromSecureStorage];
			[dict setValue:command.arguments[1] forKey:command.arguments[0]];

			[self writeToSecureStorage:dict];
			CDVPluginResult * result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
			[self.commandDelegate sendPluginResult:result callbackId: command.callbackId];
		}
	}];
}

- (void) removeItem: (CDVInvokedUrlCommand*)command {
	[self.commandDelegate runInBackground:^{
		@synchronized(self) {
			NSMutableDictionary * dict = [self readFromSecureStorage];
			[dict removeObjectForKey:command.arguments[0]];
			[self writeToSecureStorage:dict];
	 
			CDVPluginResult * result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
			[self.commandDelegate sendPluginResult:result callbackId: command.callbackId];
		}
	}];
}

- (void) clear: (CDVInvokedUrlCommand*)command {
	[self.commandDelegate runInBackground:^{
		@synchronized(self) {
			NSMutableDictionary * dict = [NSMutableDictionary new];
			[self writeToSecureStorage:dict];

			CDVPluginResult * result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
			[self.commandDelegate sendPluginResult:result callbackId: command.callbackId];
		}
	}];
}

- (void) clearIfInvalid: (CDVInvokedUrlCommand*)command {
	[self.commandDelegate runInBackground:^{
		@synchronized(self) {
			NSMutableDictionary * dict = [self readFromSecureStorage];

			if (dict == nil) {
				dict = [NSMutableDictionary new];
				[self writeToSecureStorage:dict];
			}

			CDVPluginResult * result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
			[self.commandDelegate sendPluginResult:result callbackId: command.callbackId];   
		}
	}];
}

@end
