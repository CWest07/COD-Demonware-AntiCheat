#include "stdafx.h"

bool AntiCheat::bMultiplayer;
QWORD AntiCheat::qwRandomMachineID;
BYTE AntiCheat::szRandomMAC[0x6];
char AntiCheat::szRandomConsoleSerialNumber[0xD];
char AntiCheat::szRandomConsoleID[0xC];

int XexGetModuleHandleHook(PSZ moduleName, PHANDLE hand) 
{
	if (moduleName != NULL) 
	{
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

void SetLogMessageHook(int bdAntiCheatResponses, const char* logMessage, int logMessageSize) 
{
	DWORD latestTitle = Native::XamGetCurrentTitleId();

	switch (latestTitle) 
	{
	case 0x415608C3: // Black ops 2
		if (logMessage == 0 || logMessageSize == 0) {
			Native::Write4Byte(bdAntiCheatResponses + 0x60, 0);
			memset((PVOID)(bdAntiCheatResponses + 0x1E), 0, 0x40);
			return;
		}

		if (logMessageSize == 0x36)
		{
			PBOPS2_CHAL_RESP response = (PBOPS2_CHAL_RESP)logMessage;

			response->bDebugValue = 1;
			response->dwSecurityValue = 0xFBDA;
			response->qwMachineId = AntiCheat::qwRandomMachineID;

			memcpy(response->bMacAddress, AntiCheat::szRandomMAC, 6);
			response->qwConsoleID = _atoi64(AntiCheat::szRandomConsoleID);
			response->qwSerialNumber = _atoi64(AntiCheat::szRandomConsoleSerialNumber);

			LOG_DEV("[BO2 AntiCheat] setLogMessage success!");
		}

		memcpy((PVOID)(bdAntiCheatResponses + 0x1E), (PVOID)logMessage, (logMessageSize <= 0x40) ? logMessageSize : 0x40);
		Native::Write4Byte(bdAntiCheatResponses + 0x60, (logMessageSize < 0x40) ? logMessageSize : 0x40);
		return;

	case 0x415608FC: // Ghosts
		if (logMessage == 0 || logMessageSize == 0) 
		{
			Native::Write4Byte(bdAntiCheatResponses + 0x60, 0);
			memset((PVOID)(bdAntiCheatResponses + 0x1E), 0, 0x40);
			return;
		}

		if (logMessageSize == 0x3A) 
		{
			PCOD_CHAL_RESP response = (PCOD_CHAL_RESP)logMessage;

			response->bSecurityFlag = AntiCheat::bMultiplayer ? 0x3 : 0x2;
			response->qwMachineId = AntiCheat::qwRandomMachineID;
			response->PFreeMem = AntiCheat::bMultiplayer ? 0xC84C : 0x2240;

			memcpy(response->bMacAddress, AntiCheat::szRandomMAC, 6);
			memcpy(response->cConsoleId, AntiCheat::szRandomConsoleID, sizeof(AntiCheat::szRandomConsoleID));
			memcpy(response->cConsoleSerialNumber, AntiCheat::szRandomConsoleSerialNumber, sizeof(AntiCheat::szRandomConsoleSerialNumber));

			LOG_DEV("[Ghosts AntiCheat] setLogMessage success!");
		}

		memcpy((PVOID)(bdAntiCheatResponses + 0x1E), (PVOID)logMessage, (logMessageSize <= 0x40) ? logMessageSize : 0x40);
		Native::Write4Byte(bdAntiCheatResponses + 0x60, (logMessageSize < 0x40) ? logMessageSize : 0x40);
		return;

	case 0x41560914: // Advanced warfare
		if (logMessage == 0 || logMessageSize == 0) 
		{
			Native::Write4Byte(bdAntiCheatResponses + 0x64, 0);
			memset((PVOID)(bdAntiCheatResponses + 0x22), 0, 0x40);
			return;
		}

		if (logMessageSize == 0x3A) 
		{
			PCOD_CHAL_RESP response = (PCOD_CHAL_RESP)logMessage;

			response->bSecurityFlag = AntiCheat::bMultiplayer ? 0x3 : 0x2;
			response->qwMachineId = AntiCheat::qwRandomMachineID;
			response->PFreeMem = AntiCheat::bMultiplayer ? 0x0240 : 0xEF00;

			memcpy(response->bMacAddress, AntiCheat::szRandomMAC, 6);
			memcpy(response->cConsoleId, AntiCheat::szRandomConsoleID, sizeof(AntiCheat::szRandomConsoleID));
			memcpy(response->cConsoleSerialNumber, AntiCheat::szRandomConsoleSerialNumber, sizeof(AntiCheat::szRandomConsoleSerialNumber));


			LOG_DEV("[AW AntiCheat] setLogMessage success!");
		}

		memcpy((PVOID)(bdAntiCheatResponses + 0x22), (PVOID)logMessage, (logMessageSize <= 0x40) ? logMessageSize : 0x40);
		Native::Write4Byte(bdAntiCheatResponses + 0x64, (logMessageSize < 0x40) ? logMessageSize : 0x40);
		return;

	case 0x4156091D: // Black ops 3
		if (logMessage == 0 || logMessageSize == 0)
		{
			Native::Write4Byte(bdAntiCheatResponses + 0x64, 0);
			memset((PVOID)(bdAntiCheatResponses + 0x22), 0, 0x40);
			return;
		}

		if (logMessageSize == 0x30) 
		{
			PBO3_CHAL_RESP response = (PBO3_CHAL_RESP)logMessage;

			response->bSecurityFlag = AntiCheat::bMultiplayer ? 0x3 : 0x2;

			LOG_DEV("[BO3 AntiCheat] setLogMessage success!");
		}

		memcpy((PVOID)(bdAntiCheatResponses + 0x22), (PVOID)logMessage, (logMessageSize <= 0x40) ? logMessageSize : 0x40);
		Native::Write4Byte(bdAntiCheatResponses + 0x64, (logMessageSize < 0x40) ? logMessageSize : 0x40);
		return;
	}
}

Detour<bool> OriginalLiveAntiCheat_GetChallengeResponse;
bool LiveAntiCheat_GetChallengeResponseHook(int controllerIndex, int challengeType, int *params, long long *result) 
{
	DWORD latestTitle = Native::XamGetCurrentTitleId();
	long long seed;

	switch (latestTitle)
	{
	case 0x415608C3: // Black ops 2
		if (challengeType > 7 || Native::Read4Byte(Native::Read4Byte((DWORD)params) + 8) == 0) 
		{
			LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse invalid challenge parameter with type: 0x%08X!", challengeType);
			return true;
		}

		switch (challengeType) {
			case FUNC_ID_CHECKSUM_CRC32_SPLIT: 
			{
				seed = Native::Read8Byte(Native::Read4Byte(Native::Read4Byte((DWORD)params) + 4));
				*result = 0;

				if (seed == 0x8477ADFA96D26D08) 
				{
					*result = AntiCheat::bMultiplayer ? 0xF3A57F4A23ECC797 : 0x20B0569D61F9D198;
					LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse seed #1 success!");
					return true;
				} else if (seed == 0x1E38E463BCD292A7) 
				{
					*result = AntiCheat::bMultiplayer ? 0x82F2EB24047C2CDA : 0xF02E08107E73EFBF;
					LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse seed #2 success!");
					return true;
				}

				LOG_PRINT(StrEnc("Failed #9ce6a8ee-1"));
				LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported seed detected!");
				Utils::LaunchDashboard();

				return false;
			}

			case FUNC_ID_DVAR: 
			{
				char chDvar[0x50];
				memcpy(chDvar, (char*)Native::Read4Byte(Native::Read4Byte((DWORD)params) + 4), Native::Read4Byte(Native::Read4Byte((DWORD)params) + 8));

				if (!memcmp(chDvar, StrEnc("cg_drawFPS"), 0x0A)) 
				{
					LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse cg_drawFPS dvar spoofed!");
					*result = 0;
					return true;
				} else if (!memcmp(chDvar, StrEnc("g_speed"), 0x07)) 
				{
					LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse g_speed dvar spoofed!");
					*result = 190;
					return true;
				}

				LOG_PRINT(StrEnc("Failed #bec44ccc"));
				LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse dvar %s not supported!", chDvar);
				Utils::LaunchDashboard();
				return false;
			}

			default: 
			
				LOG_DEV("[BO2 AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported challenge type: 0x%08X!", challengeType);
				Utils::LaunchDashboard();
				return false;
			}
		}
		break;

	case 0x41560914: // Advanced warfare
		switch (challengeType) 
		{
			case 0xC8: 
			{

				if (Native::Read4Byte(((DWORD)params) + 8) != FUNC_ID_CHECKSUM_CRC32) {
					LOG_DEV("[AW] LiveAntiCheat_GetChallengeResponse invalid parameter!");
					return true; // we do this because this is what the game does as well...
				}

				seed = Native::Read8Byte(Native::Read4Byte(Native::Read4Byte((DWORD)params) + 4));

				*result = 0;

				if (seed == (int)0x000A5BFE) 
				{
					*result = AntiCheat::bMultiplayer ? 0x84C6AC82 : 0xD882C85A);
					LOG_DEV("[AW] LiveAntiCheat_GetChallengeResponse success!");
					return true;
				}

				LOG_PRINT(StrEnc("Failed #9ce6a8ee-2"));
				LOG_DEV("[AW AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported seed detected!");
				Utils::LaunchDashboard();

				return false;
			}
			default: 
			{
				LOG_PRINT(StrEnc("Failed #f7eb1083"));
				LOG_DEV("[AW AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported challenge type: 0x%08X!", challengeType);
				Utils::LaunchDashboard();
				return false;
			}
		}
		break;

	case 0x4156091D: // Black ops 3
		if (challengeType > 5 || Native::Read4Byte(Native::Read4Byte((DWORD)params) + 8) == 0) 
		{
			LOG_DEV("[BO3 AntiCheat] LiveAntiCheat_GetChallengeResponse invalid challenge parameter with type: 0x%08X!", challengeType);
			return true;
		}

		switch (challengeType) 
		{
			case FUNC_ID_CHECKSUM_CRC32: 
			{
				return OriginalLiveAntiCheat_GetChallengeResponse.CallOriginal(controllerIndex, challengeType, params, result);
			}
			case FUNC_ID_DVAR: 
			{
				char chDvar[0x50];
				memcpy(chDvar, (char*)Native::Read4Byte(Native::Read4Byte((DWORD)params) + 4), Native::Read4Byte(Native::Read4Byte((DWORD)params) + 8));

				if (!memcmp(chDvar, StrEnc("cg_drawFPS"), 0x0A)) 
				{
					*result = 0;
					LOG_DEV("[BO3 AntiCheat] LiveAntiCheat_GetChallengeResponse cg_drawFPS dvar spoofed!");
					return true;
				} else if (!memcmp(chDvar, StrEnc("g_speed"), 0x07)) 
				{
					*result = 190;
					LOG_DEV("[BO3 AntiCheat] LiveAntiCheat_GetChallengeResponse g_speed dvar spoofed!");
					return true;
				}

				LOG_PRINT(StrEnc("Failed #bec44ccc"));
				LOG_DEV("[BO3 AntiCheat] LiveAntiCheat_GetChallengeResponse dvar %s not supported!", chDvar);
				Utils::LaunchDashboard();
				return false;
			}
			default: 
			{
				LOG_PRINT(StrEnc("Failed #f7eb1083"));
				LOG_DEV("[BO3 AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported challenge type: 0x%08X!", challengeType);
				Utils::LaunchDashboard();
				break;
			}
		}
		break;
	}

	Utils::LaunchDashboard();
	return false;
}

bool LiveAntiCheat_GetChallengeResponseGhostsHook(int memoryHashStructure) 
{
	short challengeType = Native::Read2Byte(memoryHashStructure + 0x08);
	int memoryHashInfo = Native::Read4Byte(memoryHashStructure + 0x34);

	switch (challengeType) 
	{
		case 0xC8: {
			if (memoryHashInfo) 
			{
				if (Native::Read4Byte(memoryHashInfo + 0x0C) != 0 || Native::Read8Byte(memoryHashInfo + 0x20) != (short)0x00003039 || Native::Read4Byte(memoryHashInfo) != 1) 
				{
					LOG_PRINT(StrEnc("Failed #9ce6a8ee-3"));
					LOG_DEV("[Ghosts AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported seed detected!");
					Utils::LaunchDashboard();
				}

				if (Native::Read4Byte(memoryHashInfo + 0x04) != 0x82100000)
					|| Native::Read4Byte(memoryHashInfo + 0x08) != 0x711400)
					|| Native::Read4Byte(memoryHashInfo + 0x10) != 0x2000))
				{
					LOG_PRINT(StrEnc("Failed #9ce6a8ee-4"));
					LOG_DEV("[Ghosts AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported start/size/crc block size detected!");
					Utils::LaunchDashboard();
				}

				Native::Write4Byte(memoryHashInfo + 0x20, 0);
				Native::Write4Byte(memoryHashInfo + 0x24, AntiCheat::bMultiplayer ? 0x4144EE73 : 0xAF78827A);
				Native::Write4Byte(memoryHashInfo + 0x0C, Native::Read4Byte(memoryHashInfo + 0x08));

				LOG_DEV("[Ghosts AntiCheat] LiveAntiCheat_GetChallengeResponse spoofed!");
			}

			break;
		}
		default:
		{
			LOG_PRINT(StrEnc("Failed #f7eb1083"));
			LOG_DEV("[Ghosts AntiCheat] LiveAntiCheat_GetChallengeResponse unsupported challenge type: 0x%08X!", challengeType);
			Utils::LaunchDashboard();
			return false;
		}
	}

	return OriginalLiveAntiCheat_GetChallengeResponse.CallOriginal(memoryHashStructure);
}

Detour<bool> OriginalbdByteBuffer_Write;
bool bdByteBuffer_WriteHook(int* buffer, const void* data, int size)
 {
	if (size == 0x6) 
	{
		memcpy((BYTE*)data, AntiCheat::szRandomMAC, 6);
		LOG_DEV("[AntiCheat] bdByteBuffer_Write spoofed mac address!");
	}
	else if (size == 0x8 && Native::Read1Byte((DWORD)data) == 0xFA) 
	{
		memcpy((BYTE*)data, &AntiCheat::qwRandomMachineID, 8);
		LOG_DEV("[AntiCheat] bdByteBuffer_Write spoofed machine id!");
	}

	return OriginalbdByteBuffer_Write.CallOriginal(buffer, data, size);
}

Detour<bool> OriginalMemoryHashInfoContinue;
bool MemoryHashInfoContinueHook(int memoryHashInfo) 
{
	if (Native::Read4Byte(memoryHashInfo + 0x0C) != 0 || Native::Read4Byte(memoryHashInfo) != 1) 
	{
		LOG_PRINT(StrEnc("Failed #9ce6a8ee-5"));
		LOG_DEV("[BO3 AntiCheat] MemoryHashInfoContinue unsupported type detected!");
		Utils::LaunchDashboard();
		return false;
	}

	Request::ServerPacketBO3Challenge* packetBO3Challenge = (Request::ServerPacketBO3Challenge*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketBO3Challenge));
	Response::ServerPacketBO3Challenge* packetBO3ChallengeResponse = (Response::ServerPacketBO3Challenge*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketBO3Challenge));

	packetBO3Challenge->dwSeedUpper = Native::Read4Byte(memoryHashInfo + 0x18);
	packetBO3Challenge->dwSeedLower = Native::Read4Byte(memoryHashInfo + 0x1C);
	packetBO3Challenge->dwStart = Native::Read4Byte(memoryHashInfo + 0x4) - 0x82140000;
	packetBO3Challenge->dwSize = Native::Read4Byte(memoryHashInfo + 0x8);
	packetBO3Challenge->dwDoSize = Native::Read4Byte(memoryHashInfo + 0x10);
	packetBO3Challenge->bMultiplayer = AntiCheat::bMultiplayer;

	// packetBO3Challenge is deallocated in func
	if (!Requests::PacketBO3Challenge(packetBO3Challenge, packetBO3ChallengeResponse)) {
		LOG_PRINT(StrEnc("Failed #c4fabd43"));
		Utils::LaunchDashboard();
		return false;
	}

	if (packetBO3ChallengeResponse->Status != Response::BO3_PACKET_SUCCESS) {
		LOG_PRINT(StrEnc("Failed #c4fabd44"));
		Utils::LaunchDashboard();
		return false;
	}

	Native::Write4Byte(memoryHashInfo + 0x18, 0);
	Native::Write4Byte(memoryHashInfo + 0x1C, packetBO3ChallengeResponse->dwHash);
	Native::Write4Byte(memoryHashInfo + 0x0C, Native::Read4Byte(memoryHashInfo + 0x08));

	Native::XEncryptedFree(packetBO3ChallengeResponse);

	LOG_DEV("[BO3 AntiCheat] MemoryHashInfoContinue success!");
	return true;
}

void AntiCheat::HandleTitle(PLDR_DATA_TABLE_ENTRY moduleHandle, DWORD dwTitle) 
{
	if ((DWORD)moduleHandle->ImageBase == 0x82000000) 
	{
		LOG_DEV("[AntiCheat] Generated random console info");
		GenerateRandomInfo();
	}

	switch (dwTitle)
	{
	case 0x415608C3: // Black ops 2
		switch (moduleHandle->TimeDateStamp) 
		{
		case 0x53643D71: // Multiplayer
			bMultiplayer = true;
			if (Config::Bypasses[0x415608C3]) 
			{
				Hooking::PatchInJump((DWORD*)0x82884CC0, (DWORD)SetLogMessageHook, false);
				Hooking::PatchInJump((DWORD*)0x8259A5E0), (DWORD)LiveAntiCheat_GetChallengeResponseHook, false);

				OriginalbdByteBuffer_Write.SetupDetour(0x8286A348, bdByteBuffer_WriteHook);

				LOG_DEV("[BO2 AntiCheat] Multiplayer hooks set!")
			}

			LOG_DEV("[BO2 AntiCheat] Bypass manually disabled...");
			return;

		case 0x518A4E7C: // Singleplayer
			bMultiplayer = false;
			if (Config::Bypasses[0x415608C3]) 
			{
				Hooking::PatchInJump((DWORD*)0x826592D0, (DWORD)SetLogMessageHook, false);
				Hooking::PatchInJump((DWORD*)0x824A7C50, (DWORD)LiveAntiCheat_GetChallengeResponseHook, false);

				OriginalbdByteBuffer_Write.SetupDetour(0x8264D4D0, bdByteBuffer_WriteHook);

				LOG_DEV("[BO2 AntiCheat] Singleplayer hooks set!")
			}
			return;
		}

		break;

	case 0x4156091D: // Black ops 3
		switch (moduleHandle->TimeDateStamp) 
		{
		case 0x5717EF77: // Multiplayer
			bMultiplayer = true;
			if (Config::Bypasses[0x4156091D]) 
			{
				Hooking::PatchInJump((DWORD*)0x827B54C8, (DWORD)SetLogMessageHook, false);

				OriginalLiveAntiCheat_GetChallengeResponse.SetupDetour(0x8253A0D8, LiveAntiCheat_GetChallengeResponseHook);
				OriginalMemoryHashInfoContinue.SetupDetour(0x82539C78, MemoryHashInfoContinueHook);

				LOG_DEV("[BO3 AntiCheat] Multiplayer hooks set!")
			}
			return;

		case 0x5717F03F: // Singleplayer
			bMultiplayer = false;
			if (Config::Bypasses[0x4156091D]) 
			{
				Hooking::PatchInJump((DWORD*)0x827A75C8, (DWORD)SetLogMessageHook, false);

				OriginalLiveAntiCheat_GetChallengeResponse.SetupDetour(0x82539310, LiveAntiCheat_GetChallengeResponseHook);
				OriginalMemoryHashInfoContinue.SetupDetour(0x82538EB0, MemoryHashInfoContinueHook);

				LOG_DEV("[BO3 AntiCheat] Zombies hooks set!")
			}
			return;
		}

		break;

	case 0x41560914: // Advanced warfare
		switch (moduleHandle->TimeDateStamp) 
		{
		case 0x55C2C3C7: // Multiplayer
			bMultiplayer = true;
			if (Config::Bypasses[0x41560914]) 
			{
				Hooking::PatchInJump((DWORD*)0x821DF510, (DWORD)SetLogMessageHook, false);
				Hooking::PatchInJump((DWORD*)0x822CC740, (DWORD)LiveAntiCheat_GetChallengeResponseHook, false);

				OriginalbdByteBuffer_Write.SetupDetour(0x821B6360, bdByteBuffer_WriteHook);

				LOG_DEV("[AW AntiCheat] Multiplayer hooks set!")
			}
			return;

		case 0x55C2C308: // Singleplayer
			bMultiplayer = false;
			if (Config::Bypasses[0x41560914]) 
			{
				Hooking::PatchInJump((DWORD*)0x826D9F28, (DWORD)SetLogMessageHook, false);
				Hooking::PatchInJump((DWORD*)0x8258C060, (DWORD)LiveAntiCheat_GetChallengeResponseHook, false);

				OriginalbdByteBuffer_Write.SetupDetour(0x826BE250, bdByteBuffer_WriteHook);

				LOG_DEV("[AW AntiCheat] Singleplayer hooks set!")
			}
			return;
		}

		break;

	case 0x415608FC: // Ghosts
		switch (moduleHandle->TimeDateStamp) 
		{
		case 0x544F01BE: // Multiplayer
			bMultiplayer = true;
			if (Config::Bypasses[0x415608FC])
			{
				Hooking::PatchInJump((DWORD*)0x827BE130, (DWORD)SetLogMessageHook, false);

				OriginalLiveAntiCheat_GetChallengeResponse.SetupDetour(0x82629F98, LiveAntiCheat_GetChallengeResponseGhostsHook);
				OriginalbdByteBuffer_Write.SetupDetour(0x827A0108, bdByteBuffer_WriteHook);

				LOG_DEV("[Ghosts AntiCheat] Multiplayer hooks set!")
			}
			return;

		case 0x544F019B: // Singleplayer
			bMultiplayer = false;
			if (Config::Bypasses[0x415608FC]) 
			{
				Hooking::PatchInJump((DWORD*)0x82647700, (DWORD)SetLogMessageHook, false);

				OriginalLiveAntiCheat_GetChallengeResponse.SetupDetour(0x825131D8, LiveAntiCheat_GetChallengeResponseGhostsHook);
				OriginalbdByteBuffer_Write.SetupDetour(0x826320B0, bdByteBuffer_WriteHook);

				LOG_DEV("[Ghosts AntiCheat] Singleplayer hooks set!")
			}
			return;
		}

		break;
	}
}

void AntiCheat::GenerateRandomInfo() 
{
	memset(&qwRandomMachineID, 0, 8);
	memset(szRandomMAC, 0, 6);
	memset(szRandomConsoleID, 0, sizeof(szRandomConsoleID));
	memset(szRandomConsoleSerialNumber, 0, sizeof(szRandomConsoleSerialNumber));

	byte* machineID = (BYTE*)Native::XEncryptedAlloc(8);
	machineID[0] = 0xFA;
	machineID[1] = 0x00;
	machineID[2] = 0x00;
	machineID[3] = 0x00;
	machineID[4] = 0x04;
	Native::XeCryptRandom(machineID + 5, 3);
	memcpy(&qwRandomMachineID, machineID, 8);
	Native::XEncryptedFree(machineID);

	bool cond = (XboxHardwareInfo->Flags & 0xF0000000) > 0x40000000;

	szRandomMAC[0] = cond ? 0x7C : 0x00;
	szRandomMAC[1] = cond ? 0xED : 0x22;
	szRandomMAC[2] = cond ? 0xD8 : 0x48;

	Native::XeCryptRandom(szRandomMAC + 3, 3);

	for (int i = 0; i < 12; i++) 
	{
		szRandomConsoleSerialNumber[i] = Utils::GenerateRandomChar();
		szRandomConsoleID[i] = Utils::GenerateRandomChar();
	}

	szRandomConsoleSerialNumber[12] = '\0';
}