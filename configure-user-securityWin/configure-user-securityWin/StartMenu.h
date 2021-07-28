#pragma once

#include <stdio.h>
#include <windows.h>
#include <lm.h>
#include <locale.h>
#include <iostream>
#include <string> 
#include <Ntsecapi.h>

#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_SUCCESS 0x00000000

void ShowUserList();
void ShowGroupList();
void UserLocalGroups(LPWSTR UsrName);
void DeleteUser();
void AddUser();
void PrintHelp();
void ShowPrivilege(LSA_HANDLE lsahPolicyHandle, PSID SID);
PSID GetSid(PWSTR user, LSA_HANDLE lsahPolicyHandle);
bool PrivToLsaString(PLSA_UNICODE_STRING plsastring, LPCWSTR string);

LSA_HANDLE GetPolicyHandle();
void LoadLib();

HMODULE hnetapi, hadvapi;

/*      netapi32.dll      */
typedef NET_API_STATUS(CALLBACK* NetUserEnumType)(LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD);
typedef NET_API_STATUS(CALLBACK* NetLocalGroupEnumType)(LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, PDWORD);
typedef NET_API_STATUS(CALLBACK* NetApiBufferFreeType)(LPVOID);
typedef NET_API_STATUS(CALLBACK* NetUserGetLocalGroupsType)(LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD);
typedef NET_API_STATUS(CALLBACK* NetUserAddType)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef NET_API_STATUS(CALLBACK* NetUserDelType)(LPCWSTR, LPCWSTR);
typedef NET_API_STATUS(CALLBACK* NetLocalGroupAddType)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef NET_API_STATUS(CALLBACK* NetLocalGroupDelType)(LPCWSTR, LPCWSTR);
typedef NET_API_STATUS(CALLBACK* NetLocalGroupAddMembersType)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);
typedef NET_API_STATUS(CALLBACK* NetLocalGroupDelMembersType)(LPCWSTR, LPCWSTR, DWORD, LPBYTE, DWORD);

NetUserEnumType NetUserEnumPtr;
NetLocalGroupEnumType NetLocalGroupPtr;
NetApiBufferFreeType NetApiBufferFreePtr;
NetUserGetLocalGroupsType NetUserGetLocalGroupsPtr;
NetUserAddType NetUserAddPtr;
NetUserDelType NetUserDelPtr;
NetLocalGroupAddType NetLocalGroupAddPtr;
NetLocalGroupDelType NetLocalGroupDelPtr;
NetLocalGroupAddMembersType NetLocalGroupAddMembersPtr;
NetLocalGroupDelMembersType NetLocalGroupDelMembersPtr;

/*      Advapi32.dll      */
typedef BOOL(CALLBACK* LookupAccountNameWType)(LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL(CALLBACK* LookupPrivilegeValueWType)(LPCWSTR, LPCWSTR, PLUID);
typedef BOOL(CALLBACK* ConvertSidToStringSidWType)(PSID, LPWSTR*);
typedef BOOL(CALLBACK* AdjustTokenPrivilegesType)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL(CALLBACK* OpenProcessTokenType)(HANDLE, DWORD, PHANDLE);
typedef NTSTATUS(CALLBACK* LsaOpenPolicyType)(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
typedef NTSTATUS(CALLBACK* LsaEnumerateAccountRightsType)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING*, PULONG);
typedef NTSTATUS(CALLBACK* LsaLookupNames2Type)(LSA_HANDLE, ULONG, ULONG, PLSA_UNICODE_STRING, PLSA_REFERENCED_DOMAIN_LIST*, PLSA_TRANSLATED_SID2*);
typedef NTSTATUS(CALLBACK* LsaAddAccountRightsType)(LSA_HANDLE, PSID, PLSA_UNICODE_STRING, ULONG);
typedef NTSTATUS(CALLBACK* LsaRemoveAccountRightsType)(LSA_HANDLE, PSID, BOOLEAN, PLSA_UNICODE_STRING, ULONG);

LookupAccountNameWType LookupAccountNameWPtr;
LookupPrivilegeValueWType LookupPrivilegeValueWPtr;
ConvertSidToStringSidWType ConvertSidToStringSidWPtr;
AdjustTokenPrivilegesType AdjustTokenPrivilegesPtr;
OpenProcessTokenType OpenProcessTokenPtr;
LsaOpenPolicyType LsaOpenPolicyPtr;
LsaEnumerateAccountRightsType LsaEnumerateAccountRightsPtr;
LsaLookupNames2Type LsaLookupNames2Ptr;
LsaAddAccountRightsType LsaAddAccountRightsPtr;
LsaRemoveAccountRightsType LsaRemoveAccountRightsPtr;


LPCWSTR privilege[38]
{
SE_ASSIGNPRIMARYTOKEN_NAME,
SE_AUDIT_NAME,
SE_BACKUP_NAME,
SE_CHANGE_NOTIFY_NAME,
SE_CREATE_GLOBAL_NAME,
SE_CREATE_PAGEFILE_NAME,
SE_CREATE_PERMANENT_NAME,
SE_CREATE_SYMBOLIC_LINK_NAME,
SE_CREATE_TOKEN_NAME,
SE_CHANGE_NOTIFY_NAME,
SE_DEBUG_NAME,
SE_ENABLE_DELEGATION_NAME,
SE_IMPERSONATE_NAME,
SE_INC_BASE_PRIORITY_NAME,
SE_INCREASE_QUOTA_NAME,
SE_INC_WORKING_SET_NAME,
SE_INTERACTIVE_LOGON_NAME,
SE_LOAD_DRIVER_NAME,
SE_LOCK_MEMORY_NAME,
SE_MACHINE_ACCOUNT_NAME,
SE_MANAGE_VOLUME_NAME,
SE_NETWORK_LOGON_NAME,
SE_PROF_SINGLE_PROCESS_NAME,
SE_RELABEL_NAME,
SE_REMOTE_SHUTDOWN_NAME,
SE_RESTORE_NAME,
SE_SECURITY_NAME,
SE_SHUTDOWN_NAME,
SE_SYNC_AGENT_NAME,
SE_SYSTEM_ENVIRONMENT_NAME,
SE_SYSTEM_PROFILE_NAME,
SE_SYSTEMTIME_NAME,
SE_TAKE_OWNERSHIP_NAME,
SE_TCB_NAME,
SE_TIME_ZONE_NAME,
SE_TRUSTED_CREDMAN_ACCESS_NAME,
SE_UNDOCK_NAME,
SE_UNSOLICITED_INPUT_NAME
};