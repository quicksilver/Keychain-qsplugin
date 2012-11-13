#import "QSKeychainSource.h"
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#define QSKeychainType @"QSKeychainType"
#define QSKeychainItemType @"QSKeychainItemType"

#define QSKeychainInternetPasswordType      @"QSKeychainInternetPasswordType"
#define QSKeychainGenericPasswordType       @"QSKeychainGenericPasswordType"
#define QSKeychainSecureNoteType            @"QSKeychainSecureNoteType"
#define QSKeychainAppleSharePasswordType    @"QSKeychainAppleSharePasswordType" /* Deprecated ? */
#define QSKeychainCertificateType           @"QSKeychainCertificateType"
#define QSKeychainKeyType                   @"QSKeychainKeyType"
#define QSKeychainIdentityType              @"QSKeychainIdentityType"

#define QSKeychainSourcePath @"QSKeychainSourcePath"

#define kSecRefValue @"v_Ref"

#define KeychainBundleID @"com.apple.keychainaccess"

NSString *errorForKeychainOSStatus(OSStatus err) {
    NSString *errorString = (NSString *)SecCopyErrorMessageString(err, NULL);
    return [errorString autorelease];
}

NSString *typeForKeychainClass(CFTypeRef itemClass, id itemType) {
    NSString *itemClassStr = itemClass;
    if ([itemClassStr isEqualToString:kSecClassGenericPassword])
        if ([NSFileTypeForHFSTypeCode([itemType unsignedIntegerValue]) isEqualToString:@"'note'"])
            return QSKeychainSecureNoteType;
        else
            return QSKeychainGenericPasswordType;
    if ([itemClassStr isEqualToString:kSecClassInternetPassword]) return QSKeychainInternetPasswordType;
    if ([itemClassStr isEqualToString:kSecClassCertificate]) return QSKeychainCertificateType;
    if ([itemClassStr isEqualToString:kSecClassIdentity]) return QSKeychainIdentityType;
    if ([itemClassStr isEqualToString:kSecClassKey]) return QSKeychainKeyType;
    return nil;
}

CFTypeRef keychainClassForType(NSString *class){
	if ([class isEqualToString:QSKeychainInternetPasswordType]) return kSecClassInternetPassword;
	if ([class isEqualToString:QSKeychainGenericPasswordType]) return kSecClassGenericPassword;
	if ([class isEqualToString:QSKeychainCertificateType]) return kSecClassCertificate;
    if ([class isEqualToString:QSKeychainIdentityType]) return kSecClassIdentity;
    if ([class isEqualToString:QSKeychainKeyType]) return kSecClassKey;
	return nil;
}

NSArray *itemsInKeychainForClass(SecKeychainRef keychainRef, CFTypeRef itemClass) {
    CFArrayRef results;
    NSDictionary *query = [NSDictionary dictionaryWithObjectsAndKeys:
                           itemClass,       kSecClass,
                           kCFBooleanTrue,  kSecReturnRef,
                           kCFBooleanTrue,  kSecReturnAttributes,
                           [NSArray arrayWithObject:(id)keychainRef], kSecMatchSearchList,
                           kSecMatchLimitAll,  kSecMatchLimit,
                           nil];
    OSStatus err = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&results);
	if (err != noErr) {
        NSLog(@"Failed to get items in Keychain %p: %@ %ld", keychainRef, errorForKeychainOSStatus(err), (long)err);
        return nil;
    }
    return [(NSArray *)results autorelease];
}

QSObject *objectForKeychainDict(NSDictionary *keychainDict) {
    /* Filter NSNulls from the dictionary */
    NSSet *existingKeys = [keychainDict keysOfEntriesPassingTest:^BOOL(id key, id obj, BOOL *stop) { return (!obj || obj != [NSNull null]); }];
    keychainDict = [keychainDict dictionaryWithValuesForKeys:[existingKeys allObjects]];

    NSString *label = [keychainDict objectForKey:kSecAttrLabel];
    if (!label) {
        NSData *subjectData = [keychainDict objectForKey:kSecAttrSubject];
        label = [[[NSString alloc] initWithData:subjectData encoding:NSASCIIStringEncoding] autorelease];
    }

    QSObject *itemObject = [QSObject objectWithName:label];
    [itemObject setObject:keychainDict forType:QSKeychainItemType];
    [itemObject setPrimaryType:QSKeychainItemType];

    return itemObject;
}

BOOL isKeychainLocked(NSString *keychainPath, BOOL *locked) {
    SecKeychainRef keychainRef = NULL;
    OSStatus err = SecKeychainOpen([keychainPath fileSystemRepresentation], &keychainRef);
    if (err) {
        NSLog(@"Failed opening Keychain %@: %@ (%ld)", keychainPath, errorForKeychainOSStatus(err), (long)err);
        return NO;
    }
    SecKeychainStatus status;
    err = SecKeychainGetStatus(keychainRef, &status);
    if (err) {
        NSLog(@"Failed getting status of Keychain %@: %@ (%ld)", keychainPath, errorForKeychainOSStatus(err), (long)err);
        CFRelease(keychainRef);
        return NO;
    }
    if (locked)
        *locked = !(status & kSecUnlockStateStatus);
    CFRelease(keychainRef);
    return YES;
}

NSData *dataForKeychainItem(SecKeychainItemRef itemRef) {
    if (!itemRef)
        return nil;

    UInt32 length;
    void *data;
    OSStatus status = SecKeychainItemCopyContent(itemRef, NULL, NULL, &length, &data);
    if (status != noErr) {
        NSLog(@"Error getting contents of Keychain item %@: %@ %ld", itemRef, errorForKeychainOSStatus(status), (long)status);
        return nil;
    }
    NSData *passwordData = [NSData dataWithBytes:data length:length];
    SecKeychainItemFreeContent(NULL, data);
    return passwordData;
}

OSStatus keychainEventCallback(SecKeychainEvent keychainEvent, SecKeychainCallbackInfo *info, void *context) {
    if (keychainEvent == kSecLockEvent || keychainEvent == kSecUnlockEvent) {
        NSLog(@"Keychain %@ was %@", info->keychain, (keychainEvent == kSecLockEvent ? @"locked" : @"unlocked"));
        UInt32 pathLength = MAXPATHLEN;
        char path[pathLength];
        SecKeychainGetPath(info->keychain, &pathLength, path);

        NSData *pathData = [NSData dataWithBytesNoCopy:path length:pathLength freeWhenDone:NO];
        NSString *keychainPath = [[[NSString alloc] initWithData:pathData encoding:NSUTF8StringEncoding] autorelease];

        NSString *identifier = [NSString stringWithFormat:@"%@:%@", @"[Keychain]", keychainPath];
        QSObject *keychainObject = [QSObject objectWithIdentifier:identifier];
        if (keychainObject) {
            /* Force the icon to refresh */
            [keychainObject unloadIcon];
            [keychainObject loadIcon];
        }
    }
    return noErr;
}


@implementation QSKeychainSource
- (id)init {
    self = [super init];
    if (self) {
        OSStatus err = SecKeychainAddCallback(keychainEventCallback, kSecEveryEventMask, self);
        if (err != noErr)
            NSLog(@"Error adding Keychain event callback: %@ %ld", errorForKeychainOSStatus(err), (long)err);
    }
    return self;
}

- (void)dealloc {
    OSStatus err = SecKeychainRemoveCallback(keychainEventCallback);
    if (err != noErr)
        NSLog(@"Error removing Keychain event callback: %@ %ld", errorForKeychainOSStatus(err), (long)err);
    [super dealloc];
}

- (BOOL)indexIsValidFromDate:(NSDate *)indexDate forEntry:(NSDictionary *)theEntry{
    NSDate *modDate = [[[NSFileManager defaultManager] attributesOfItemAtPath:[@"~/Library/Preferences/com.apple.Keychain.plist" stringByResolvingSymlinksInPath] error:nil] fileModificationDate];
    return [modDate compare:indexDate] == NSOrderedAscending;
}

- (NSImage *)iconForEntry:(NSDictionary *)dict{
    return [QSResourceManager imageNamed:KeychainBundleID];
}

- (NSString *)identifierForObject:(QSObject *)object
{
    NSString *identifier = nil;
    if ([[object primaryType] isEqualToString:QSKeychainType]) {
        NSString *path = [object primaryObject];
        if (path)
            identifier = [@"[Keychain]:" stringByAppendingString:path];
    } else if ([[object primaryType] isEqualToString:QSKeychainItemType]) {
        NSDictionary *info = [object primaryObject];
        if (info) {
            NSString *label = [info objectForKey:kSecAttrLabel];
            identifier = [@"[KeychainItem]:" stringByAppendingString:(label ? label : [[info objectForKey:kSecRefValue] description])];
        }
    }
    return identifier;
}

- (QSObject *)parentOfObject:(QSObject *)object {
    QSObject *parent = nil;
    if ([[object primaryType] isEqualToString:QSKeychainItemType]) {
        NSString *keychainPath = [object objectForMeta:QSKeychainSourcePath];
        parent = [QSObject objectWithIdentifier:[@"[Keychain]:" stringByAppendingString:keychainPath]];
    } else if ([[object primaryType] isEqualToString:QSKeychainType]) {
        NSString *path = [[NSBundle bundleWithIdentifier:KeychainBundleID] bundlePath];
        parent = [QSObject fileObjectWithPath:path];
    }
    return parent;
}

- (NSArray *)objectsForEntry:(NSDictionary *)theEntry {
	NSMutableArray *objects = [NSMutableArray arrayWithCapacity:1];
    QSObject *newObject;

	NSArray *searchList = nil;
    OSStatus err = noErr;
    err = SecKeychainCopySearchList((CFArrayRef *)&searchList);
    if (err != noErr) {
        NSLog(@"Failed to get Keychain search list: %@ (%ld)", errorForKeychainOSStatus(err), (long)err);
        return nil;
    }
    for (id search in searchList) {
        UInt32 				kcPathLen = MAXPATHLEN;
        char 				kcPath[kcPathLen];
        err = SecKeychainGetPath((SecKeychainRef)search, &kcPathLen, kcPath);
        if (err != noErr) {
            NSLog(@"Failed to get path of Keychain: %@ (%ld)", errorForKeychainOSStatus(err), (long)err);
            continue;
        }
        NSString *path = [NSString stringWithCString:kcPath encoding:NSUTF8StringEncoding];

        newObject = [QSObject fileObjectWithPath:path];
        [newObject setObject:path forType:QSKeychainType];
        [newObject setPrimaryType:QSKeychainType];
        [newObject setLabel:[[path lastPathComponent] stringByDeletingPathExtension]];
        if (newObject)
            [objects addObject:newObject];
    }
    CFRelease(searchList);
	return objects;
}


- (NSString *)detailsOfObject:(QSObject *)object{
    NSDictionary *info = [object objectForType:QSKeychainItemType];
	if (info) {
		NSString *details = [info objectForKey:kSecAttrDescription];
		if (!details)
			details = [info objectForKey:kSecAttrAccount];
		return details;			
	}
	return nil; 
}

- (BOOL)loadChildrenForObject:(QSObject *)object {
    if ([object objectForType:QSKeychainType]) {
        /* Children of a Keychain */
        NSString *keychainPath = [object objectForType:QSKeychainType];

        NSMutableArray *children = [NSMutableArray arrayWithCapacity:1];

        SecKeychainRef keychainRef = NULL;
        OSStatus status;

        status = SecKeychainOpen([keychainPath UTF8String], &keychainRef);
        if (status != noErr) {
            NSLog(@"Failed to open Keychain at path %@: %@ (%ld)", keychainPath, errorForKeychainOSStatus(status), (long)status);
            return NO;
        }
        NSSet *keychainClasses = [NSSet setWithObjects:kSecClassGenericPassword,
                                  kSecClassInternetPassword,
                                  kSecClassCertificate,
                                  kSecClassKey,
                                  kSecClassIdentity,
                                  nil];
        for (id keychainClass in keychainClasses) {
            NSArray *results = itemsInKeychainForClass(keychainRef, keychainClass);
            for (NSDictionary *itemDict in results) {
                id object = objectForKeychainDict(itemDict);
                if (object) {
                    [children addObject:object];
                    [object setObject:keychainPath forMeta:QSKeychainSourcePath];
                }
            }
        }

        CFRelease(keychainRef);
        if (children) {
            [object setChildren:children];
            return YES;
        }
    } else if ([[object primaryType] isEqualToString:QSKeychainItemType]) {
        /* Children of keychain items */
        NSDictionary *info = [object primaryObject];
        NSString *type = typeForKeychainClass([info objectForKey:kSecClass], [info objectForKey:kSecAttrType]);
        if ([type isEqualToString:QSKeychainSecureNoteType]) {
            SecKeychainItemRef itemRef = (SecKeychainItemRef)[info objectForKey:kSecRefValue];
            NSData *noteData = dataForKeychainItem(itemRef);

            id propertyList = [NSPropertyListSerialization propertyListFromData:noteData
                                                               mutabilityOption:NSPropertyListImmutable
                                                                         format:NULL
                                                               errorDescription:NULL];

            QSObject *noteObject = [QSObject objectWithString:[propertyList objectForKey:@"NOTE"]];
            [object setChildren:[NSArray arrayWithObject:noteObject]];
            return YES;
        }
    } else {
        /* Load children for Keychain Access.app */
		[object setChildren:[self objectsForEntry:nil]];
		return YES;
	}
    return NO;
}

// Object Handler Methods
- (void)setQuickIconForObject:(QSObject *)object{
    [object setIcon:[QSResourceManager imageNamed:KeychainBundleID]];
}

- (BOOL)loadIconForObject:(QSObject *)object {
	NSImage *icon = nil;
    if ([[object primaryType] isEqualToString:QSKeychainItemType]) {
        NSDictionary *itemDict = [object objectForType:QSKeychainItemType];
        NSString *type = typeForKeychainClass([itemDict objectForKey:kSecClass], [itemDict objectForKey:kSecAttrType]);

        if ([type isEqualToString:QSKeychainInternetPasswordType]) {
            icon = [QSResourceManager imageNamed:@"KeychainURLIcon"];
        } else if ([type isEqualToString:QSKeychainGenericPasswordType]) {
            icon = [QSResourceManager imageNamed:@"KeychainKeyIcon"];
        } else if ([type isEqualToString:QSKeychainSecureNoteType]) {
            icon = [QSResourceManager imageNamed:@"KeychainSecureNoteIcon"];
        } else if ([type isEqualToString:QSKeychainAppleSharePasswordType]) {
            icon = [QSResourceManager imageNamed:@"KeychainNetVolIcon"];
        } else if ([type isEqualToString:QSKeychainCertificateType]) {
            icon = [QSResourceManager imageNamed:@"KeychainCertificateIcon"];
        } else if ([type isEqualToString:QSKeychainKeyType]) {
            icon = [QSResourceManager imageNamed:@"KeychainKeyIcon"];
        }
    } else if ([[object primaryType] isEqualToString:QSKeychainType]) {
        NSString *keychainPath = [object objectForType:QSKeychainType];
        BOOL state;
        BOOL res = isKeychainLocked(keychainPath, &state);
        if (res) {
            icon = [QSResourceManager imageNamed:(state ? @"KeychainLockedIcon" : @"KeychainUnlockedIcon")];
        }

        if (!icon)
            icon = [QSResourceManager imageNamed:KeychainBundleID];
    }
	
	if (icon) {
		[object updateIcon:icon];
		return YES;
	}
	
	return NO;
}
- (BOOL)drawIconForObject:(QSObject *)object inRect:(NSRect)rect flipped:(BOOL)flipped {
	if (NSWidth(rect) <= 32)
        return NO;
	NSImage *image = [QSResourceManager imageNamed:KeychainBundleID];

    [image setSize:[[image bestRepresentationForSize:rect.size] size]];
	//[image adjustSizeToDrawAtSize:rect.size];
	[image setFlipped:flipped];
	[image drawInRect:rect fromRect:rectFromSize([image size]) operation:NSCompositeSourceOver fraction:1.0];

	if ([object iconLoaded]) {
		NSImage *cornerBadge = [object icon];
		if (cornerBadge != image) {
			[cornerBadge setFlipped:flipped]; 
			NSImageRep *bestBadgeRep = [cornerBadge bestRepresentationForSize:rect.size];
			[cornerBadge setSize:[bestBadgeRep size]];
			NSRect badgeRect = rectFromSize([cornerBadge size]);

			//NSPoint offset=rectOffset(badgeRect,rect,2);
			badgeRect = centerRectInRect(badgeRect, rect);
			badgeRect = NSOffsetRect(badgeRect, 0, NSHeight(rect) / 2 - NSHeight(badgeRect) / 2);

			[[NSColor colorWithDeviceWhite:1.0 alpha:0.8] set];
			//NSRectFillUsingOperation(NSInsetRect(badgeRect,-3,-3),NSCompositeSourceOver);
			[[NSColor colorWithDeviceWhite:0.75 alpha:1.0] set];
			//NSFrameRectWithWidth(NSInsetRect(badgeRect,-5,-5),2);
			[cornerBadge drawInRect:badgeRect fromRect:rectFromSize([cornerBadge size]) operation:NSCompositeSourceOver fraction:1.0];
		}
	}
	return YES;
}

@end


#define kQSKeychainItemShowAction           @"QSKeychainItemShowAction"
#define kQSKeychainItemCopyPasswordAction   @"QSKeychainItemCopyPasswordAction"
#define kQSKeychainItemGetPasswordAction    @"QSKeychainItemGetPasswordAction"
#define kQSKeychainItemPastePasswordAction  @"QSKeychainItemPastePasswordAction"
#define kQSKeychainItemCopyAccountAction    @"QSKeychainItemCopyAccountAction"
#define kQSKeychainItemGetAccountAction     @"QSKeychainItemGetAccountAction"
#define kQSKeychainItemPasteAccountAction   @"QSKeychainItemPasteAccountAction"

#define kQSKeychainLockAction               @"QSKeychainLockAction"
#define kQSKeychainUnlockAction             @"QSKeychainUnlockAction"

@implementation QSKeychainActionProvider

- (NSArray *)validActionsForDirectObject:(QSObject *)dObject indirectObject:(QSObject *)iObject {
    if ([[dObject primaryType] isEqualToString:QSKeychainType]) {
        NSString *keychainPath = [dObject primaryObject];
        BOOL state = NO;
        BOOL res = isKeychainLocked(keychainPath, &state);
        if (res)
            return [NSArray arrayWithObject:(state ? kQSKeychainUnlockAction : kQSKeychainLockAction)];
    } else if ([[dObject primaryType] isEqualToString:QSKeychainItemType]) {
        NSDictionary *info = [dObject primaryObject];
        NSString *itemType = typeForKeychainClass([info objectForKey:kSecClass], [info objectForKey:kSecAttrType]);
        if ([itemType isEqualToString:QSKeychainGenericPasswordType]
            || [itemType isEqualToString:QSKeychainInternetPasswordType]) {
            return [NSArray arrayWithObjects:kQSKeychainItemCopyPasswordAction, kQSKeychainItemGetPasswordAction, kQSKeychainItemPastePasswordAction,
                    kQSKeychainItemCopyAccountAction, kQSKeychainItemGetAccountAction, kQSKeychainItemPasteAccountAction,
                    nil];
        }
    }
    return nil;
}

- (QSObject *) showKeychainItem:(QSObject *)dObject{
    /* TODO */
	//AXUIElementRef app=AXUIElementCreateApplication(1099);
    return nil;
}

- (NSString *)passwordForKeychainObject:(QSObject *)dObject {
	NSDictionary *info = [dObject primaryObject];
    if (!info)
        return nil;

	SecKeychainItemRef itemRef = (SecKeychainItemRef)[info objectForKey:kSecRefValue];
    NSData *passwordData = dataForKeychainItem(itemRef);

	return [[[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding] autorelease];;
}

- (BOOL)copyPasswordForObject:(QSObject *)dObject {
	NSString *password = [self passwordForKeychainObject:dObject];

	if (password) {
		NSPasteboard *pboard = [NSPasteboard generalPasteboard];
		[pboard declareTypes:[NSArray arrayWithObjects:NSStringPboardType, QSPrivatePboardType, nil] owner:self];
		[pboard setString:password forType:NSStringPboardType];
		[pboard setString:password forType:QSPrivatePboardType];
	}
	return password != nil;
}

- (QSObject *)copyPassword:(QSObject *)dObject {
	[self copyPasswordForObject:dObject];
	return nil;
}

- (QSObject *)pastePassword:(QSObject *)dObject {
	if ([self copyPasswordForObject:dObject]) {
        /* Let the Keychain access window disappear */
        [NSThread sleepForTimeInterval:1.0];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"WindowsShouldHide" object:self];
        [[NSApp keyWindow] orderOut:self];
        QSForcePaste();
	} else {
		NSBeep();
		NSLog(@"Could not find password for %@", dObject);
	}
	return nil;
}

- (QSObject *)getPassword:(QSObject *)dObject {
	NSString *password = [self passwordForKeychainObject:dObject];
	if (!password)
        return nil;
    QSObject *object = [QSObject objectWithString:password];
    [object setParentID:[dObject identifier]];
    return object;
}

- (NSString *)accountForKeychainObject:(QSObject *)dObject {
	NSDictionary *info = [dObject primaryObject];

	return info ? [info objectForKey:kSecAttrAccount] : nil;
}

- (BOOL)copyAccountForObject:(QSObject *)dObject {
	NSString *account = [self accountForKeychainObject:dObject];

	if (account) {
		NSPasteboard *pboard = [NSPasteboard generalPasteboard];
		[pboard declareTypes:[NSArray arrayWithObjects:NSStringPboardType, nil] owner:self];
		[pboard setString:account forType:NSStringPboardType];
	}
	return account != nil;
}

- (QSObject *)copyAccount:(QSObject *)dObject {
	[self copyAccountForObject:dObject];
	return nil;
}

- (QSObject *)pasteAccount:(QSObject *)dObject {
	if ([self copyAccountForObject:dObject]) {
        [[NSNotificationCenter defaultCenter] postNotificationName:@"WindowsShouldHide" object:self];
        [[NSApp keyWindow] orderOut:self];
        QSForcePaste();
	} else {
		NSBeep();
		NSLog(@"Could not find password for %@", dObject);
	}
	return nil;
}

- (QSObject *)getAccount:(QSObject *)dObject {
	NSString *account = [self accountForKeychainObject:dObject];
	if (!account)
        return nil;
    QSObject *object = [QSObject objectWithString:account];
    [object setParentID:[dObject identifier]];
    return object;
}

- (BOOL)changeKeychain:(NSString *)keychainPath lock:(BOOL)lock {
    OSStatus err = noErr;
    SecKeychainRef keychainRef = NULL;
    err = SecKeychainOpen([keychainPath fileSystemRepresentation], &keychainRef);
    if (err != noErr) {
        NSLog(@"Failed to open Keychain at path %@: %@ (%ld)", keychainPath, errorForKeychainOSStatus(err), (long)err);
        return NO;
    }
    if (lock)
        err = SecKeychainLock(keychainRef);
    else
        err = SecKeychainUnlock(keychainRef, 0, NULL, false);

    if (err != noErr) {
        NSLog(@"Failed to %@ Keychain at path %@: %@ %ld", (lock ? @"lock" : @"unlock"), keychainPath, errorForKeychainOSStatus(err), (long)err);
    }
    CFRelease(keychainRef);
    return (err != noErr);
}

- (QSObject *)unlockKeychain:(QSObject *)dObject {
    NSString *keychainPath = [dObject objectForType:QSKeychainType];
    if (keychainPath) {
        [self changeKeychain:keychainPath lock:NO];
    }
    return dObject;
}

- (QSObject *)lockKeychain:(QSObject *)dObject {
    NSString *keychainPath = [dObject objectForType:QSKeychainType];
    if (keychainPath) {
        [self changeKeychain:keychainPath lock:YES];
    }
    return dObject;
}

/*
 show_key("10.0.1.100")
 
 on show_key(theKey)
 tell application "System Events"
 tell application process "Keychain Access"
 tell table 1 of scroll area 1 of group 1 of window 1
 set theValues to value of text field 1 of rows
 repeat with i from 1 to count theValues
 if length of item i of theValues = (length of theKey) + 2 then
 if item i of theValues ends with theKey then
 
 select row i
 return i
 
 end if
 end if
 --log item i of theValues
 --log theKey
 end repeat
	end tell
	end tell
	end tell
	return 0
	end show_key
 
 */

@end

