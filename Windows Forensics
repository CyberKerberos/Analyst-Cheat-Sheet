Control Set:  
`SYSTEM > Select > "Current"`

Computer Name:  
`SYSTEM > ControlSetXXX > Control > ComputerName > "ComputerName"`

Current Timezone:  
`SYSTEM > ControlSetXXX > Control > TimeZoneInformation > "TimeZoneKeyName"`

Operating System Bit Version:  
`SOFTWARE > Microsoft > Windows NT > CurrentVersion > "BuildLabEx"`

System Install Date:  
`SOFTWARE > Microsoft > WindowsNT > CurrentVersion > "InstallDate"`  
NOTE:- Decode it from Unix format.

Last Logged On User:  
`SOFTWARE > Microsoft > Windows > CurrentVersion > Authentication > LogonUI > "LastLoggedOnUser"`

Last Shutdown Time:  
`SYSTEM > ControlSetXXX > Control > Windows > "ShutdownTime"`  
NOTE:- Decode it from Hex format.

Autostart Applications:  
`NTUSER.dat > Software > Microsoft > Windows > CurrentVersion > Run`

Searched terms in Windows:  
`NTUSER.dat > Software > Microsoft > Windows > CurrentVersion > Explorer > WordWheelQuery`

Recently Accessed Files:  
`NTUSER.dat > Software > Microsoft > Windows > CurrentVersion > Explorer > RecentDocs`

Windows Run Queries:  
`NTUSER.dat > Software > Microsoft > Windows > CurrentVersion > Explorer > RunMRU`

Relative Identifier for a user:  
`SAM > Domains > Account > Users > Names > User`

User Created Accounts (Look for Relative Identifiers > 1000):  
`SAM > Domains > Account > Users > Names`

Machine Identifier (Last 12 bytes):  
`SAM > Domains > Account > "V"`  
NOTE:- Group into 3 sets of 4, convert to little endian and convert from hex to dec.

USB devices connected:  
`SYSTEM > ControlSetXXX > Enum > USBSTOR`

Serial Number of USB device mounted:  
`SYSTEM > MountedDevices`

Network Connections:  
`SOFTWARE > Microsoft > Windows NT > CurrentVersion > NetworkList`

Install date of applications:  
`Amcache.hve > {GUID} > InventoryApplication > 'ProgramID' > "InstallDate"`

Last executed time of applications:  
`NTUSER.dat > Software > Microsoft > Windows > CurrentVersion > Explorer > UserAssist> {GUID} (ROT13 encoded)`

Pagefile cleared at shutdown? (Used for swapping RAM):  
`SYSTEM > ControlSetXXX > Control > Session Manager > Memory Management > "ClearPageFileAtShutdown"`  
NOTE:- If value is 0, then look for the pagefile.sys file for the memory capture.

computer IP
`‘SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`
If DHCP look at the field DhcpIPAddress.
For  DHCP LeaseObtainedTime look at the field LeaseObtainedTime.

What is the computer SID?

For the SID we will have to calculate it from the SAM hive under the key: ‘SAM\Domains\Account’ and take the last 12 bytes of the ‘V’ field, split into 3 sections of 4 bytes, swap the endianness and convert to decimal.
I suggest utilizing [_RegRipper_](https://github.com/keydet89/RegRipper3.0), a parser which has a lot of plugins which does all the calculation for us in order to parse the data.

OS information: 
‘Windows/System32’ > licence.rtf

The computer timezone
`SYSTEM\controlSet001 \Control \TimeZoneInformation`

User connect information
`SAM\Domains\Accounts\Users`

Executable last time executed: prefetch files

Skype conversation
`Export the **main.db** located at ‘Users/Hunter/AppData/Roaming/Skype/hunterehpt` looking into chat table for usernames, table messages for conversation, accounts table for email addresses 

Outlook backup 
`Users/Hunter/Documents/Outlook Files/backup.pst’.`

checked for installed-at-one-point applications in the registry

`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall’

‘SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall’`

USB Information: 

`SYSTEM\ControlSet001\Enum\USBSTOR`

traffic manipulation tool was executed
UserAssist, AppCompatCache and Amcache.hve

For lnk files we can find them here 
`Users/Hunter/AppData/Roaming/Microsoft/Windows/Recent`

If a directory is opened in a view, `UsrClass.dat` hive will indefinitely have an entry for it unless manually deleted. Shellbags contains metadata like timestamps and absolute path. It can be helpful in timelining and proving the access to folders by a particular user account.

Open up `UsrClass.dat` in ShellBagsExplorer;

Jumplist are stored at ‘Users/User/AppData/Roaming/Microsoft/Windows/Recent’ by default under 2 directories: ‘AutomaticDestinations’ & ‘CustomDestinations’. (JumpListExplorer)



Master Boot Record magic number
`33 C0 8E D0 BC 00 7C 8E`

messaging app installed on the victim machine
`Users →Semah → Check Downloads /AppData`

Whatsapp messages
`Users →Semah →AppData →whatsapp →Databases →msgstore.db(Export it )Open the file in whatsapp viewer .check the msg`

URLs:
`opens the Autopsy →Users →Semah →AppData →Roaming →Mozilla →Firefox →profiles →pyb51x2n.default-release →places.sqlite → look at the moz_places Section`

password the user submitted to the login page?

`HINT : Save the profile folder of Firefox in your system. And Open it into the [passwordfox](https://www.nirsoft.net/utils/passwordfox.html). This application is used to Show the firefox saved username and passwords. The profile Folder contains the saved username and passwords.`




