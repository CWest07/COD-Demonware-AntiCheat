# COD-Demonware-AntiCheat
Dynamically and correctly handle the security challenges issued by the Demonware server on Xbox 360 Call of Duty platforms to avoid detection of modified consoles and .text section edits.

By intercepting a buffer that copies the security data, we are able to change/spoof/edit the results in any way we'd like. The 2 biggest challenges are the flags used to detect modified consoles, and a CRC32 / CRC32 split checksum on the .text (code section).
In attempt to detect modified consoles, all COD games running demonware's anticheat, use mainly 2 methods. First is attempting to get a handle to 'xbdm.xex' by calling GetModuleHandleA("xbdm.xex") and testing the results to see if a valid handle was found, indicating a modified console. Eventually the 'xbdm.xex' string was obfuscated, but by simply hooking the systems GetModuleHandle function, we can log the location and the name of any module checked, and by using register 12 in PowerPC, we can know the exact function that attempted to get access to this handle. Second method is by running a CRC32 (CRC32 split for BO2) on the .text section of the game including the import table to detect hooked imports. These CRC32/CRC32 split checksums are required to be updated each title update AND dashboard update, due to the checksum including the imports table.

Example bypassing handle checks: 
```
int XexGetModuleHandleHook(PSZ moduleName, PHANDLE hand) 
{
    int dwLR = 0;
    __asm { mflr dwLR }

    // This will now give us the address of where the code will jump to once it's finished here, which just so happens to also show us where it was called from.
    // We can take the address from here, and usually it leads us directly to any security related code.
    LOG_DEV("r12: 0x%08X", dwLR);

    // null can be used for the game to get a hold of it's self lol..
    if (moduleName != NULL) 
    {
        LOG_DEV("Module Name: %s", moduleName);
        
        // Easily bypass all handle checks by making a list of bad handles and if they are checked, report as not loaded
        for (int i = 0; i < NUMOF(szBlacklistedPlugins); i++) 
        {
            if (memcmp(moduleName, szBlacklistedPlugins[i], strlen(szBlacklistedPlugins[i])) == 0) 
            {
                *hand = 0;
                return 0xC0000225;
            }
        }
     }

    return XexGetModuleHandle(moduleName, hand);
}
```
