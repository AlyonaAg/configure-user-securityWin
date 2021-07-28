#pragma once
#include "StartMenu.h"



void LoadLib()
{
    hnetapi = LoadLibraryA("netapi32.dll");
    hadvapi = LoadLibraryA("Advapi32.dll");

    if (hnetapi && hadvapi)
    {
        /*      netapi32.dll      */    
        NetUserEnumPtr = (NetUserEnumType)GetProcAddress(hnetapi, "NetUserEnum");
        NetLocalGroupPtr = (NetLocalGroupEnumType)GetProcAddress(hnetapi, "NetLocalGroupEnum");
        NetApiBufferFreePtr = (NetApiBufferFreeType)GetProcAddress(hnetapi, "NetApiBufferFree");
        NetUserGetLocalGroupsPtr = (NetUserGetLocalGroupsType)GetProcAddress(hnetapi, "NetUserGetLocalGroups");
        NetUserAddPtr = (NetUserAddType)GetProcAddress(hnetapi, "NetUserAdd");
        NetUserDelPtr = (NetUserDelType)GetProcAddress(hnetapi, "NetUserDel");
        NetLocalGroupAddPtr = (NetLocalGroupAddType)GetProcAddress(hnetapi, "NetLocalGroupAdd");
        NetLocalGroupDelPtr=(NetLocalGroupDelType)GetProcAddress(hnetapi, "NetLocalGroupDel");
        NetLocalGroupAddMembersPtr = (NetLocalGroupAddMembersType)GetProcAddress(hnetapi, "NetLocalGroupAddMembers");
        NetLocalGroupDelMembersPtr = (NetLocalGroupDelMembersType)GetProcAddress(hnetapi, "NetLocalGroupDelMembers");

        /*      Advapi32.dll      */
        LookupAccountNameWPtr = (LookupAccountNameWType)GetProcAddress(hadvapi, "LookupAccountNameW");
        LookupPrivilegeValueWPtr = (LookupPrivilegeValueWType)GetProcAddress(hadvapi, "LookupPrivilegeValueW");
        ConvertSidToStringSidWPtr = (ConvertSidToStringSidWType)GetProcAddress(hadvapi, "ConvertSidToStringSidW");
        AdjustTokenPrivilegesPtr = (AdjustTokenPrivilegesType)GetProcAddress(hadvapi, "AdjustTokenPrivileges");
        OpenProcessTokenPtr = (OpenProcessTokenType)GetProcAddress(hadvapi, "OpenProcessToken");
        LsaOpenPolicyPtr = (LsaOpenPolicyType)GetProcAddress(hadvapi, "LsaOpenPolicy");
        LsaEnumerateAccountRightsPtr = (LsaEnumerateAccountRightsType)GetProcAddress(hadvapi, "LsaEnumerateAccountRights");
        LsaLookupNames2Ptr = (LsaLookupNames2Type)GetProcAddress(hadvapi, "LsaLookupNames2");
        LsaAddAccountRightsPtr = (LsaAddAccountRightsType)GetProcAddress(hadvapi, "LsaAddAccountRights");
        LsaRemoveAccountRightsPtr = (LsaRemoveAccountRightsType)GetProcAddress(hadvapi, "LsaRemoveAccountRights");
    }
}


void ShowUserList()
{
    DWORD dwlevel = 0;
    DWORD dwfilter = 0;
    USER_INFO_0* theEntries = new USER_INFO_0[20];
    DWORD dwprefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD dwentriesread;
    DWORD dwtotalentries;
    NET_API_STATUS result;

    PSID SID = NULL;
    LPWSTR strSID = NULL;

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();

    result = NetUserEnumPtr(NULL, dwlevel, dwfilter, (LPBYTE*)&theEntries, dwprefmaxlen, &dwentriesread, &dwtotalentries, NULL);

    std::cout << "\tUsers:" << std::endl;
    for (int i = 0; i < dwentriesread; i++)
    {
        std::cout << "\t" << i + 1 << ": ";
        std::wcout << theEntries[i].usri0_name << std::endl;

        if (lsahPolicyHandle == NULL)
        {
            std::cout << "\t\t(to get information about SID and privileges run the program as administrator)" << std::endl;
            continue;
        }

        SID = GetSid(theEntries[i].usri0_name, lsahPolicyHandle);
        ConvertSidToStringSidWPtr(SID, &strSID);
        std::wcout << "\t   SID: " << strSID << std::endl;

        UserLocalGroups(theEntries[i].usri0_name);

        std::cout << "\t   Privilege:" << std::endl;
        ShowPrivilege(lsahPolicyHandle, SID);

        LocalFree((HLOCAL)strSID);
    }
    NetApiBufferFreePtr(theEntries);
}

void ShowGroupList()
{
    DWORD dwlevel = 0;
    DWORD dwfilter = 0;
    GROUP_INFO_0* theEntries = new GROUP_INFO_0[20];
    DWORD dwprefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD dwentriesread;
    DWORD dwtotalentries;
    NET_API_STATUS result;

    PSID  SID;
    LPWSTR strSID = NULL;

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();

    result = NetLocalGroupPtr(NULL, dwlevel, (LPBYTE*)&theEntries, dwprefmaxlen, &dwentriesread, &dwtotalentries, NULL);

    std::cout << "\tGroups:" << std::endl;
    for (int i = 0; i < dwentriesread; i++)
    {
        std::cout << "\t" << i + 1 << ": ";
        std::wcout << theEntries[i].grpi0_name << std::endl;   

        if (lsahPolicyHandle == NULL)
        {
            std::cout << "\t\t(to get information about SID and privileges run the program as administrator)" << std::endl;
            continue;
        }

        SID = GetSid(theEntries[i].grpi0_name, lsahPolicyHandle);
        ConvertSidToStringSidWPtr(SID, &strSID);
        std::wcout << "\t   SID: " << strSID << std::endl;
        LocalFree((HLOCAL)strSID);

        std::cout << "\t   Privilege:" << std::endl;
        ShowPrivilege(lsahPolicyHandle, SID);
    }
    NetApiBufferFreePtr(theEntries);
}

void ShowPrivilege(LSA_HANDLE lsahPolicyHandle, PSID SID)
{
    PLSA_UNICODE_STRING plsaStr;
    ULONG uVal = 0;
    NET_API_STATUS nStatus = LsaEnumerateAccountRightsPtr(lsahPolicyHandle, SID, &plsaStr, &uVal);

    if (uVal == 0)
        std::cout << "\t\t- (no privileges)" << std::endl;

    for (int i = 0; i < uVal; i++)
    {
        std::wcout << "\t\t- " <<plsaStr->Buffer << std::endl;
        plsaStr++;
    }
}

void UserLocalGroups(LPWSTR user) {
    DWORD dwlevel = 0;
    DWORD dwfilter = 0;
    LPLOCALGROUP_USERS_INFO_0 ptmpbuf;
    DWORD dwprefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD dwentriesread;
    DWORD dwtotalentries;
    NET_API_STATUS result;
    LPLOCALGROUP_USERS_INFO_0 pbuf = NULL;
  
    DWORD i, dwtotalcount = 0;
    result = NetUserGetLocalGroupsPtr(NULL, user, dwlevel, LG_INCLUDE_INDIRECT, (LPBYTE*)&pbuf, dwprefmaxlen, &dwentriesread, &dwtotalentries);

    if (result == NERR_Success && (ptmpbuf = pbuf) != NULL)
    {
        std::cout << "\t   Local groups:" << std::endl;
        for (i = 0; i < dwentriesread; i++)
        {
            if (ptmpbuf == NULL)
            {
                std::cout << "\t\t- (access problems)" << std::endl;
                break;
            }
            std::wcout << "\t\t- " << ptmpbuf->lgrui0_name << std::endl;
            ptmpbuf++;
            dwtotalcount++;
        }
    }
    
    if (pbuf != NULL)
        NetApiBufferFreePtr(pbuf);
}

void AddUser()
{
    std::wstring login, password;

    std::cout << "\tEnter user login: ";
    std::getline(std::wcin, login);

    std::cout << "\tEnter user password: ";
    std::getline(std::wcin, password);
    std::wcin.clear();

    USER_INFO_1 ui;
    DWORD dwlevel = 1;
    DWORD dwerror = 0;
    NET_API_STATUS result = 0;

    ui.usri1_name = (LPWSTR)login.c_str();
    ui.usri1_password= (LPWSTR)password.c_str();
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    result = NetUserAddPtr(NULL, dwlevel, (LPBYTE)&ui, &dwerror);
    if (result == NERR_Success)
        std::cout << ("\tuser added successfully.") << std::endl;
    else
        std::cout << ("\terror occurred while adding user.") << std::endl;
}

void DeleteUser()
{
    std::wstring login;
    std::cout << "\tEnter user name: ";
    std::getline(std::wcin, login);

    NET_API_STATUS result = 0;

    result = NetUserDelPtr(NULL, (LPWSTR)login.c_str());

    if (result == NERR_Success)
        std::cout << ("\tuser deleted successfully.") << std::endl;
    else
        std::cout << ("\terror occurred while deleting user.") << std::endl;
}

void AddGroup()
{
    std::wstring group;

    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    LOCALGROUP_INFO_0 ui;
    DWORD dwlevel = 0;
    DWORD dwerror = 0;
    NET_API_STATUS result = 0;

    ui.lgrpi0_name = (LPWSTR)group.c_str();

    result = NetLocalGroupAddPtr(NULL, dwlevel, (LPBYTE)&ui, &dwerror);
    if (result == NERR_Success)
        std::cout << ("\tgroup added successfully.") << std::endl;
    else
        std::cout << ("\terror occurred while adding group.") << std::endl;
}

void DeleteGroup()
{
    std::wstring group;
    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    NET_API_STATUS result = 0;

    result = NetLocalGroupDelPtr(NULL, (LPWSTR)group.c_str());
    if (result == NERR_Success)
        std::cout << ("\tgroup deleted successfully.") << std::endl;
    else
        std::cout << ("\terror occurred while deleting group.") << std::endl;
}

void AddUserToGroup()
{
    std::wstring login, group;

    std::cout << "\tEnter user name: ";
    std::getline(std::wcin, login);

    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    NET_API_STATUS result = 0;

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    LOCALGROUP_MEMBERS_INFO_0 pBuf;

    if (lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)login.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tuser not found." << std::endl;
        return;
    }

    pBuf.lgrmi0_sid = SID;

    result = NetLocalGroupAddMembersPtr(NULL, (LPWSTR)group.c_str(), 0, (LPBYTE)&pBuf, 1);
    if (result == NERR_Success)
        std::cout << "\tmember was successfully added." << std::endl;
    else 
        std::cout << "\terror occurred while adding member." << std::endl;
}

void DelUserFromGroup()
{
    std::wstring login, group;

    std::cout << "\tEnter user name: ";
    std::getline(std::wcin, login);

    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    NET_API_STATUS result = 0;

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    LOCALGROUP_MEMBERS_INFO_0 pBuf;

    if (lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)login.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tuser not found." << std::endl;
        return;
    }

    pBuf.lgrmi0_sid = SID;

    result = NetLocalGroupDelMembersPtr(NULL, (LPWSTR)group.c_str(), 0, (LPBYTE)&pBuf, 1);
    if (result == NERR_Success)
        std::cout << "\tmember was successfully deleted." << std::endl;
    else
        std::cout << "\terror occurred while deleting member." << std::endl;
}

void AddPrivilege(LSA_HANDLE lsahPolicyHandle, PSID SID)
{
    std::string number_string;
    int number;
    NTSTATUS result = 0;

    std::cout << "\tPrivilege:" << std::endl;
    for (unsigned int i = 0; i < 38; i++)
        std::wcout << "\t" << i + 1 << ": " << privilege[i] << std::endl;
    std::cout << "\twhat privilege to add? ";
    std::getline(std::cin, number_string);
    number = std::stoi(number_string);

    if (number <= 0 || number > 38)
    {
        std::cout << "\tincorrect number." << std::endl;
        return;
    }

    LSA_UNICODE_STRING LsaString;
    PrivToLsaString(&LsaString, privilege[number - 1]);

    result = LsaAddAccountRightsPtr(lsahPolicyHandle, SID, &LsaString, 1);
    if (result == STATUS_SUCCESS)
        std::cout << "\tprivilege was successfully added." << std::endl;
    else
        std::cout << "\terror occurred while adding privilege." << std::endl;
}

void AddPrivilegeUser()
{
    std::wstring login;

    std::cout << "\tEnter user name: ";
    std::getline(std::wcin, login);

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    if(lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)login.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tuser not found." << std::endl;
        return;
    }

    AddPrivilege(lsahPolicyHandle, SID);
}

void AddPrivilegeGroup()
{
    std::wstring group;

    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    if (lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)group.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tgroup not found." << std::endl;
        return;
    }

    AddPrivilege(lsahPolicyHandle, SID);
}

void DelPrivilege(LSA_HANDLE lsahPolicyHandle, PSID SID)
{
    std::string number_string;
    int number;
    NTSTATUS result = 0;

    std::cout << "\tPrivilege:" << std::endl;
    for (unsigned int i = 0; i < 38; i++)
        std::wcout << "\t" << i + 1 << ": " << privilege[i] << std::endl;
    std::cout << "\twhat privilege to delete? ";
    std::getline(std::cin, number_string);
    number = std::stoi(number_string);

    if (number <= 0 || number > 38)
    {
        std::cout << "\tincorrect number." << std::endl;
        return;
    }

    LSA_UNICODE_STRING LsaString;
    PrivToLsaString(&LsaString, privilege[number - 1]);

    result = LsaRemoveAccountRightsPtr(lsahPolicyHandle, SID, FALSE, &LsaString, 1);
    if (result == STATUS_SUCCESS)
        std::cout << "\tprivilege was successfully deleted." << std::endl;
    else
        std::cout << "\terror occurred while deleting privilege." << std::endl;
}

void DelPrivilegeUser()
{
    std::wstring login;

    std::cout << "\tEnter user name: ";
    std::getline(std::wcin, login);

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    if (lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)login.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tuser not found." << std::endl;
        return;
    }

    DelPrivilege(lsahPolicyHandle, SID);
}

void DelPrivilegeGroup()
{
    std::wstring group;

    std::cout << "\tEnter group name: ";
    std::getline(std::wcin, group);

    LSA_HANDLE lsahPolicyHandle = GetPolicyHandle();
    if (lsahPolicyHandle == NULL)
    {
        std::cout << "\t\t(run the program as administrator)" << std::endl;
        return;
    }

    PSID SID = GetSid((PWSTR)group.c_str(), lsahPolicyHandle);
    if (SID == NULL)
    {
        std::cout << "\tgroup not found." << std::endl;
        return;
    }

    DelPrivilege(lsahPolicyHandle, SID);
}

PSID GetSid(PWSTR user, LSA_HANDLE lsahPolicyHandle)
{
    NET_API_STATUS result;
    LSA_UNICODE_STRING name;
    PLSA_REFERENCED_DOMAIN_LIST referenced_domains;
    PLSA_TRANSLATED_SID2 SID;

    name.Buffer = user;
    name.Length = wcslen(user) * sizeof(WCHAR);
    name.MaximumLength = (wcslen(user) + 1) * sizeof(WCHAR);

    result = LsaLookupNames2Ptr(lsahPolicyHandle, 0x80000000, 1, &name, &referenced_domains, &SID);
    return SID->Sid;
}

bool PrivToLsaString(PLSA_UNICODE_STRING plsastring, LPCWSTR string)
{
    DWORD dwlen = 0;
    if (NULL == plsastring)
        return FALSE;
    if (NULL != string) {
        dwlen = wcslen(string);
        if (dwlen > 0x7ffe)
            return FALSE;
    }
    plsastring->Buffer = (WCHAR*)string;
    plsastring->Length = (USHORT)dwlen * sizeof(WCHAR);
    plsastring->MaximumLength = (USHORT)(dwlen + 1) * sizeof(WCHAR);
    return TRUE;
}


void PrintHelp()
{
    std::cout << "\tCommand:" << std::endl;
    std::cout << "\t1:  \"users\" - show user list" << std::endl;
    std::cout << "\t2:  \"groups\" - show group list" << std::endl;
    std::cout << "\t3:  \"adduser\" - add new user" << std::endl;
    std::cout << "\t4:  \"deluser\" - delete user" << std::endl;
    std::cout << "\t5:  \"addgroup\" - add new group" << std::endl;
    std::cout << "\t6:  \"delgroup\" - delete group" << std::endl;
    std::cout << "\t7:  \"addug\" - add user to group" << std::endl;
    std::cout << "\t8:  \"delug\" - delete user from group" << std::endl;
    std::cout << "\t9:  \"addpru\" - add privilege to user" << std::endl;
    std::cout << "\t10: \"delpru\" - delete privilege to user" << std::endl;
    std::cout << "\t11: \"addprg\" - add privilege to group" << std::endl;
    std::cout << "\t12: \"delprg\" - delete privilege to group" << std::endl;
}


LSA_HANDLE GetPolicyHandle(void)
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE lsahPolicyHandle = NULL;
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    NTSTATUS result = LsaOpenPolicyPtr(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
    return lsahPolicyHandle;
}


int main()
{    
    setlocale(LC_ALL, "Rus");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    LoadLib();
    std::string command;
    while (1)
    {
        printf("# ");

        if (!std::getline(std::cin, command))
            break;

        if (command == "users")
            ShowUserList();
        else if (command == "groups")
            ShowGroupList();
        else if (command == "adduser")
            AddUser();
        else if (command == "deluser")
            DeleteUser();
        else if (command == "addgroup")
            AddGroup();
        else if (command == "delgroup")
            DeleteGroup();
        else if (command == "addug")
            AddUserToGroup();
        else if (command == "delug")
            DelUserFromGroup();
        else if (command == "addpru")
            AddPrivilegeUser();
        else if (command == "delpru")
            DelPrivilegeUser();
        else if (command == "addprg")
            AddPrivilegeGroup();
        else if (command == "delprg")
            DelPrivilegeGroup();
        else if (command == "help")
            PrintHelp();
        else if (command == "exit")
            break;
        else
            std::cout << "error command." << std::endl;

        command.clear();
    }

    command.clear();
    return 0;
}