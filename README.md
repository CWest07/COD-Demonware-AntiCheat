# COD-Demonware-AntiCheat
Dynamically and correctly handle the security challenges issued by the Demonware server on Xbox 360 Call of Duty platforms to avoid detection of modified consoles and .text section edits.

By intercepting a buffer that copies the security data, we are able to change/spoof/edit the results in any way we'd like. The 2 biggest challenges are the flags used to detect modified consoles, and a CRC32 / CRC32 split checksum on the .text (code section).
In attempt to detect modified consoles, all COD games running demonware's anticheat, use mainly 2 methods. First is attempting to get a handle to 'xbdm.xex' by calling GetModuleHandleA("xbdm.xex") and testing the results to see if a valid handle was found, indicating a modified console. Eventually the 'xbdm.xex' string was obfuscated, but by simply hooking the systems GetModuleHandle function, we can log the location and the name of any module checked, and by using register 12 in PowerPC, we can know the exact function that attempted to get access to this handle. Second method is by running a CRC32 (CRC32 split for BO2) on the .text section of the game including the import table to detect hooked imports. These CRC32/CRC32 split checksums are required to be updated each title update AND dashboard update, due to the checksum including the imports table.

This will also prevent and bypass any type of machine/console ban on 3 out of the 4 games, due to Black Ops III using certificates to verify and ban machines/consoles with the help of Microsoft. This was done once it was realized that users on modified consoles could actually machine/console ban retail users, simply by spoofing to their machine/console information and sending bad challenge results. This machine/console information was easily accessable in memory for every player in the game, and didn't require any sort of special host connection to access, and was even accessable in pre-game lobbys. To my knowledge this feature has been disabled on all 3 of those games due to that.

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

CRC32 algorithm: 
```
private static uint crc32(uint crc, byte[] buf, uint index, uint length) 
{
    uint crc_0 = crc & 0xFFFFFFFF;
    for (uint x = index; x < index + length; x++)
    {
        crc_0 = crc32_tab[((crc_0 & 0xFF) ^ buf[x]) & 0xFF] ^ (crc_0 >> 8);
    }
    return crc_0;
}

private static uint CalculateHash(uint crc, byte[] data, uint StartIndex, uint DataLen, uint dwDoSize) 
{
    uint crc_0 = crc;
    uint dwSize = DataLen;
    while (true) 
    {
        uint position = (uint)data.Length - dwSize;
        if (StartIndex != 0)
            position = (DataLen - dwSize) + StartIndex;
        if (dwSize == 0)
            break;
        if (dwSize < dwDoSize)
            dwDoSize = dwSize;
        crc_0 = crc32(crc_0, data, position, dwDoSize);
        dwSize -= dwDoSize;
    }
    return crc_0;
}
```
