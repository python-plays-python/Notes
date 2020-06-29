# Windows Registry

The Registry contains information used by Windows and your programs. The Registry helps the operating system manage the computer, it helps programs use the computer’s resources, and it provides a location for keeping custom settings you make in both Windows and your programs.

For example, when you change the Windows desktop, the changes are stored in the Registry. 

The Registry is essentially a database. Its information is stored on disk for the most part, though dynamic information also exists in the computer’s memory. (That dynamic information concerns the computer’s hardware and operating state.) All the information is organized by using a structure similar to folders in the file storage system.

The top level of the Registry contains hives, each of which starts with the curious word HKEY.

## Registry Hives

Name 	            Abbreviation 	Contents

HKEY_CLASSES_ROOT 	HKCR 	        Information used by programs for file association and for sharing information.

HKEY_CURRENT_USER 	HKCU 	        Settings and configuration for the current user.

HKEY_LOCAL_MACHINE 	HKLM 	        Settings and configuration for all users.

HKEY_USERS 	        HKU 	        Settings and configuration for all users on the computer; the information in HKCU is copied from this hive when the user logs in.

HKEY_CURRENT_CONFIG N/A 	        Hardware information about the PC’s resources and configuration.

## Keys 

Beneath the hives are folders, or keys. Keys can also have subkeys, just as folders have subfolders

Keys contain values. Every value has a name and data. Unlike the old ini files, the data can be something other than text, including numeric values and binary information. You can find several values in a single key, or a key can be empty or contain only subkeys.

As with files and folders, values stored in the Registry are found by following a pathname that gives the location of a specific key or value. For example, the following pathname to the key gives the location where Adobe Acrobat Reader 8.0 is installed on the computer:

`HKCUSoftwareAdobeAcrobat Reader8.0InstallPath`

The abbreviation HKCU for HKEY_CURRENT_USER is used in the preceding line. It’s followed by the subkeys Software, Adobe, Acrobat Reader, 8.0, and, finally, InstallPath. In the InstallPath key is a value that holds data in the form of text. The text is the pathname for the storage system location where Acrobat Reader 8.0 is installed.

Keys, like pathnames to files, can get long. Sometimes, a key name that’s too long to fit on a single line must be wrapped, such as

`HKCUSoftwareMicrosoftWindowsCurrentVersionExplorerVisualEffectsCursorShadow`

This key contains a binary value that determines whether Windows displays a shadow on the mouse pointer. The line is too long to fit on the page, so it wraps.
