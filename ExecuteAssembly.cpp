// ExecuteAssembly.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <mscoree.h>
#include <MetaHost.h>
#include <strsafe.h>
#include <string>
#include <iostream>


//Make sure to add $(NETFXKitsDir)Include\um to your include directories
#import "mscorlib.tlb" raw_interfaces_only, auto_rename				\
    high_property_prefixes("_get","_put","_putref")		\
    rename("ReportEvent", "InteropServices_ReportEvent")
#pragma comment(lib, "mscoree.lib")
using namespace mscorlib;

ICorRuntimeHost* g_Runtime = NULL;

HANDLE g_OrigninalStdOut = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdOut = INVALID_HANDLE_VALUE;
HANDLE g_OrigninalStdErr = INVALID_HANDLE_VALUE;
HANDLE g_CurrentStdErr = INVALID_HANDLE_VALUE;


HANDLE g_hSlot = INVALID_HANDLE_VALUE;
LPCSTR SlotName = "\\\\.\\mailslot\\myMailSlot";

//Taken from : https://docs.microsoft.com/en-us/windows/win32/ipc/writing-to-a-mailslot
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName)
{
	g_hSlot = CreateMailslotA(lpszSlotName,
		0,                             // no maximum message size 
		MAILSLOT_WAIT_FOREVER,         // no time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL); // default security

	if (g_hSlot == INVALID_HANDLE_VALUE)
	{
		printf("CreateMailslot failed with %d\n", GetLastError());
		return FALSE;
	}
	else printf("Mailslot created successfully.\n");
	return TRUE;
}

// Mostly from : https://docs.microsoft.com/en-us/windows/win32/ipc/reading-from-a-mailslot
BOOL ReadSlot(std::string& output)
{
	CONST DWORD szMailBuffer = 424; //Size comes from https://docs.microsoft.com/en-us/windows/win32/ipc/about-mailslots?redirectedfrom=MSDN
	DWORD cbMessage, cMessage, cbRead;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	LPVOID achID[szMailBuffer];
	DWORD cAllMessages;
	HANDLE hEvent;
	OVERLAPPED ov;

	cbMessage = cMessage = cbRead = 0;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

	fResult = GetMailslotInfo(g_hSlot, // mailslot handle 
		(LPDWORD)NULL,               // no maximum message size 
		&cbMessage,                   // size of next message 
		&cMessage,                    // number of messages 
		(LPDWORD)NULL);              // no read time-out 

	if (!fResult)
	{
		printf("GetMailslotInfo failed with %d.\n", GetLastError());
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		printf("Waiting for a message...\n");
		return TRUE;
	}

	cAllMessages = cMessage;

	while (cMessage != 0)  // retrieve all messages
	{
		// Allocate memory for the message. 

		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(g_hSlot,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			printf("ReadFile failed with %d.\n", GetLastError());
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}
		output += lpszBuffer;

		fResult = GetMailslotInfo(g_hSlot,  // mailslot handle 
			(LPDWORD)NULL,               // no maximum message size 
			&cbMessage,                   // size of next message 
			&cMessage,                    // number of messages 
			(LPDWORD)NULL);              // no read time-out 

		if (!fResult)
		{
			printf("GetMailslotInfo failed (%d)\n", GetLastError());
			return FALSE;
		}
	}
	GlobalFree((HGLOBAL)lpszBuffer);
	CloseHandle(hEvent);
	return TRUE;
}


HRESULT LoadCLR()
{
	HRESULT hr;
	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	BOOL bLoadable;

	// Open the runtime
	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	if (FAILED(hr))
		goto Cleanup;

	//DotNet version v4.0.30319
	hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
	if (FAILED(hr))
		goto Cleanup;

	// Check if the runtime is loadable (this will fail without .Net v4.x on the system)

	hr = pRuntimeInfo->IsLoadable(&bLoadable);
	if (FAILED(hr) || !bLoadable)
		goto Cleanup;

	// Load the CLR into the current process
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&g_Runtime);
	if (FAILED(hr))
		goto Cleanup;

	// Start the CLR.
	hr = g_Runtime->Start();
	if (FAILED(hr))
		goto Cleanup;

Cleanup:

	if (pMetaHost)
	{
		pMetaHost->Release();
		pMetaHost = NULL;
	}
	if (pRuntimeInfo)
	{
		pRuntimeInfo->Release();
		pRuntimeInfo = NULL;
	}
	if (FAILED(hr) && g_Runtime)
	{
		g_Runtime->Release();
		g_Runtime = NULL;
	}

	return hr;
}


HRESULT CallMethod(std::string assembly, std::string args, std::string& outputString) {
	HRESULT hr = S_OK;
	SAFEARRAY* psaArguments = NULL;
	IUnknownPtr pUnk = NULL;
	_AppDomainPtr pAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfo* pEntryPt = NULL;
	SAFEARRAYBOUND bounds[1];
	SAFEARRAY* psaBytes = NULL;
	LONG rgIndices = 0;
	wchar_t* w_ByteStr = NULL;
	LPWSTR* szArglist = NULL;
	int nArgs = 0;
	VARIANT vReturnVal;
	VARIANT vEmpty;
	VARIANT vtPsa;

	SecureZeroMemory(&vReturnVal, sizeof(VARIANT));
	SecureZeroMemory(&vEmpty, sizeof(VARIANT));
	SecureZeroMemory(&vtPsa, sizeof(VARIANT));
	vEmpty.vt = VT_NULL;
	vtPsa.vt = (VT_ARRAY | VT_BSTR);

	//Get a pointer to the IUnknown interface because....COM
	hr = g_Runtime->GetDefaultDomain(&pUnk);
	if (FAILED(hr))
		goto Cleanup;


	// Get the current app domain
	hr = pUnk->QueryInterface(IID_PPV_ARGS(&pAppDomain));
	if (FAILED(hr))
		goto Cleanup;

	// Load the assembly
	//Establish the bounds for our safe array
	bounds[0].cElements = (ULONG)assembly.size();
	bounds[0].lLbound = 0;

	//Create a safe array and fill it with the bytes of our .net assembly
	psaBytes = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(psaBytes);
	memcpy(psaBytes->pvData, assembly.data(), assembly.size());
	SafeArrayUnlock(psaBytes);

	//Load the assembly into the app domain
	hr = pAppDomain->Load_3(psaBytes, &pAssembly);
	if (FAILED(hr))
	{

		SafeArrayDestroy(psaBytes);
		goto Cleanup;
	}

	SafeArrayDestroy(psaBytes);

	// Find the entry point
	hr = pAssembly->get_EntryPoint(&pEntryPt);

	if (FAILED(hr))
		goto Cleanup;

	//This will take our arguments and format them so they look like command line arguments to main (otherwise they are treated as a single string)



	if (args.empty())
	{

		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);

	}
	else
	{
		//Convert to wide characters
		w_ByteStr = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
		mbstowcs(w_ByteStr, (char*)args.data(), args.size() + 1);
		szArglist = CommandLineToArgvW(w_ByteStr, &nArgs);


		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
		for (long i = 0; i < nArgs; i++)
		{
			BSTR strParam1 = SysAllocString(szArglist[i]);
			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
		}
	}

	psaArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	hr = SafeArrayPutElement(psaArguments, &rgIndices, &vtPsa);

	//Execute the function.  Note that if you are executing a function with return data it will end up in vReturnVal
	hr = pEntryPt->Invoke_3(vEmpty, psaArguments, &vReturnVal);

	//Reset our Output handles (the error message won't show up if they fail, just for debugging purposes)
	if (!SetStdHandle(STD_OUTPUT_HANDLE, g_OrigninalStdOut))
	{
		std::cerr << "ERROR: SetStdHandle REVERTING stdout failed." << std::endl;
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, g_OrigninalStdErr))
	{
		std::cerr << "ERROR: SetStdHandle REVERTING stderr failed." << std::endl;
	}

	//Read from our mail slot
	if (!ReadSlot(outputString))
		printf("Failed to read from mail slot");

Cleanup:
	VariantClear(&vReturnVal);
	if (NULL != psaArguments)
		SafeArrayDestroy(psaArguments);
	psaArguments = NULL;
	pAssembly->Release();

	return hr;
}


std::string ExecuteAssembly(std::string& assembly, std::string args)
{
	HRESULT hr;
	std::string output = "";

	//Create our mail slot
	if (!MakeSlot(SlotName))
	{
		printf("Failed to create mail slot");
		return output;
	}
	HANDLE hFile = CreateFileA(SlotName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	//Load the CLR
	hr = LoadCLR();
	if (FAILED(hr))
	{
		output = "failed to load CLR";
		goto END;
	}
	printf("Successfully loaded CLR\n");
	//Set stdout and stderr to our mail slot
	g_OrigninalStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	g_OrigninalStdErr = GetStdHandle(STD_ERROR_HANDLE);


	if (!SetStdHandle(STD_OUTPUT_HANDLE, hFile))
	{
		output = "SetStdHandle stdout failed.";
		goto END;
	}
	if (!SetStdHandle(STD_ERROR_HANDLE, hFile))
	{
		output = "SetStdHandle stderr failed.";
		goto END;
	}


	hr = CallMethod(assembly, args, output);
	if (FAILED(hr))
		output = "failed to call method";

END:
	if (g_hSlot != INVALID_HANDLE_VALUE)
		CloseHandle(g_hSlot);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return output;
}


int main()
{
	DWORD lpNumberOfBytesRead = 0;
	DWORD dwFileSize = 0;
	PVOID lpFileBuffer = NULL;

	//arguments seperated by a space : "kerberoast /tgtdeleg" or just ""
	std::string args = "";

	//Read the .net exe from disk
	HANDLE hFile = CreateFileA("C:\\Users\\admin\\Desktop\\Seatbelt.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}


	dwFileSize = GetFileSize(hFile, NULL);
	lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL))
	{
		return 1;
	}

	//No real reason to do this, it just works with the code I already had
	std::string assemblyStr((char*)lpFileBuffer, lpNumberOfBytesRead);

	//Execute the Assembly
	std::string response = ExecuteAssembly(assemblyStr, args);

	VirtualFree(lpFileBuffer, dwFileSize, MEM_DECOMMIT | MEM_RELEASE);
	CloseHandle(hFile);

	printf("Output from string = %s", response.c_str());

}

