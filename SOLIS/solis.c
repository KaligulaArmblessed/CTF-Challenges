#include <stdio.h> 
#include <stdlib.h> 
#include <stdint.h> 
#include <string.h>

#include <strsafe.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// DEFINE
#define ROOTDIR L"C:\\\\Root\\"
#define MAX_LEN_PASSWORD 0x500
#define MAX_NOTE 0x100

// GLOBAL VARIABLES
HKEY hRoot = 0; 
wchar_t wCurrentUser[0x100] = {0};
wchar_t checking_strings[0x10][0x20] = {L"..\\"};
char * Notes[MAX_NOTE] = {0}; 
int NoteSize[MAX_NOTE] = {0};
int NoteIdx = 0; 

// STRUCTS
struct override_data {
    char buf[0x50]; 
    int registry_role; 
};

// FUNCTIONS
void print_banner() {
    printf("=================================================================================\n");
    printf("                 $$$$$$\\   $$$$$$\\  $$\\       $$$$$$\\  $$$$$$\\ \n");
    printf("                $$  __$$\\ $$  __$$\\ $$ |      \\_$$  _|$$  __$$\\ \n"); 
    printf("                $$ /  \\__|$$ /  $$ |$$ |        $$ |  $$ /  \\__| \n"); 
    printf("                \\$$$$$$\\  $$ |  $$ |$$ |        $$ |  \\$$$$$$\\ \n");  
    printf("                 \\____$$\\ $$ |  $$ |$$ |        $$ |   \\____$$\\ \n");
    printf("                $$\\   $$ |$$ |  $$ |$$ |        $$ |  $$\\   $$ | \n");
    printf("                \\$$$$$$  | $$$$$$  |$$$$$$$$\\ $$$$$$\\ \\$$$$$$  | \n");
    printf("                 \\______/  \\______/ \\________|\\______| \\______/ \n"); 

    printf("        .__ .___.__  __..__..  ..  ..___.      __..   , __..___..___.  . \n"); 
    printf("        [__)[__ [__)(__ |  ||\\ ||\\ |[__ |     (__  \\./ (__   |  [__ |\\/| \n"); 
    printf("        |   [___|  \\.__)|__|| \\|| \\|[___|___  .__)  |  .__)  |  [___|  |    \n"); 
                                                                
    printf("================================================================================\n");
    printf("               >> Engineered by Kaligula Armblessed Industries <<\n");
}

void print_menu() {
    printf("===================================== MENU =====================================\n");
    printf("Select an option: \n");
    printf("1. Login\n");
    printf("2. View all employees\n"); 
    printf("3. Create account\n"); 
    printf("4. Delete account\n");
    printf("5. Create key/value\n"); 
    printf("6. Read key/value\n"); 
    printf("7. Write value\n"); 
    printf("8. Delete key/value\n"); 
    printf("9. Create file\n"); 
    printf("10. Read file\n"); 
    printf("11. Write file\n");
    printf("12. Delete file\n");
    printf("13. Logout\n");
    printf("14. Store note\n"); 
    printf("15. Read note\n"); 
    printf("16. Delete note\n"); 
    printf("17. Admin override\n");  
    printf("18. Exit\n");
    printf("=================================================================================\n");
    printf(">> "); 
}

// HELPER FUNCTIONS
void strip_newline(char * buf) {
    buf[strcspn(buf, "\r\n")] = '\0';
}

int read_wstr(wchar_t * wBuf, DWORD bufSize) {
    int result = -1; 
    char buf[0x500] = {0}; 

    if (bufSize < 0x500) {
        fgets(buf, bufSize, stdin); 
    } else {
        fgets(buf, sizeof(buf), stdin); 
    }
    strip_newline(buf); 
    result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf, -1, wBuf, bufSize);
    return result; 
}

int has_invalid_chars(const wchar_t *str) {
    return wcspbrk(str, L"<>:\"/\\|?*") != NULL;
}

int enumerate_subkey(HKEY key) {
    LSTATUS status = 0; 
    wchar_t wSubKey[0x500] = {0}; 
    DWORD index = 0; 
    
    while (1) {
        memset(wSubKey, 0x0, sizeof(wSubKey));
        DWORD subkeyNameLength = ARRAYSIZE(wSubKey);
        status = RegEnumKeyExW(key, index, wSubKey, &subkeyNameLength, NULL, NULL, NULL, NULL);

        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }

        wprintf(L"Entry %d: %ls\n", index, wSubKey); 
        index += 1; 
    }
    return 0; 
}

int enumerate_values(HKEY key) {
    LSTATUS status = 0; 
    wchar_t wValue[0x500] = {0}; 
    DWORD index = 0; 

    while (1) {
        memset(wValue, 0x0, sizeof(wValue)); 
        DWORD valueLength = ARRAYSIZE(wValue); 
        status = RegEnumValueW(key, index, wValue, &valueLength, NULL, NULL, NULL, NULL); 

        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }

        wprintf(L"Value %d: %ls\n", index, wValue); 
        index += 1;
    }
    return index; 
}

int enumerate_employees() {
    enumerate_subkey(hRoot); 
    return 0; 
}

int get_employee_username(wchar_t * wUsername, int usernameLength) {
    char buf[0x500] = {0};

    printf("Current account entries: \n"); 
    enumerate_employees(); 

    printf("Select account >> "); 
    read_wstr(wUsername, usernameLength); 
    return 0; 
}

int create_registry_key(wchar_t * wUsername) {
    HKEY hNewKey = NULL; 
    wchar_t wBuf[0x100] = {0}; 
    wchar_t wNewKey[0x500] = {0}; 
    DWORD disposition = 0; 
    int result = 0; 
    LSTATUS status = -1; 
    HRESULT hr = -1; 

    printf("Enter name of new registry key >> "); 
    read_wstr(wBuf, ARRAYSIZE(wBuf)); 

    hr = StringCchCatW(wNewKey, ARRAYSIZE(wNewKey), (STRSAFE_LPCWSTR)wUsername); 
    hr = StringCchCatW(wNewKey, ARRAYSIZE(wNewKey), L"\\"); 
    hr = StringCchCatW(wNewKey, ARRAYSIZE(wNewKey), wBuf); 

    status = RegCreateKeyExW(hRoot, wNewKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, NULL, &hNewKey, &disposition); 

    if (status != ERROR_SUCCESS) {
        printf("[!] Key creation failed.\n"); 
        return -1; 
    }

    status = RegCloseKey(hNewKey); 
    hNewKey = NULL;
    wprintf(L"[+] New key created: %ls\n", wNewKey);  
    return 0; 
}

HKEY get_subkey_handle(wchar_t * wUsername) {  
    LSTATUS status = -1;  
    HRESULT hr = -1;
    int result = 0;

    char buf[0x10] = {0};
    wchar_t wBuf[0x100] = {0}; 
    wchar_t wSubKey[0x500] = {0}; 
    HKEY hSubKey = NULL;

    printf("Use subkey? (y/n) >> ");
    fgets(buf, 0x10, stdin); 
    strip_newline(buf); 

    if (strncmp(buf, "y", 1) == 0 || strncmp(buf, "Y", 1) == 0) {
        printf("Enter subkey >> "); 
        result = read_wstr(wBuf, ARRAYSIZE(wBuf)); 
        if (result == 0) {
            printf("[!] An error occurred.\n"); 
            return NULL;
        }

        hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), (STRSAFE_LPCWSTR)wUsername); 
        hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), L"\\"); 
        hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), wBuf); 

        status = RegOpenKeyExW(hRoot, wSubKey, 0, KEY_ALL_ACCESS, &hSubKey); 

    } else {
        status = RegOpenKeyExW(hRoot, (LPCWSTR)wUsername, 0, KEY_ALL_ACCESS, &hSubKey); 
    }

    if (status != ERROR_SUCCESS) {
        printf("[!] Subkey open failed.\n"); 
        return NULL;
    } 

    return hSubKey; 
}

int modify_registry_value(HKEY hSubKey) {
    LSTATUS status = -1; 
    int result = 0; 
    unsigned int option = 0; 
    int c; 

    DWORD value_type = -1; 
    char value[0x500] = {0}; 
    wchar_t wValue[0x500] = {0}; 
    char * dataBuf = NULL; 

    HANDLE heap = GetProcessHeap(); 
    if (heap == NULL) {
        printf("[!] Heap initialization failed.\n"); 
        return -1; 
    }

    printf("Enter value >> "); 
    fgets(value, sizeof(value), stdin); 
    strip_newline(value); 
    result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, wValue, ARRAYSIZE(wValue));

    if (wcscmp(wValue, L"DirPath") == 0) {
        printf("[!] Modification of DirPath is not allowed.\n"); 
        return -1; 
    }

    printf("Data type: \n"); 
    printf("1. String\n"); 
    printf("2. DWORD\n"); 
    printf(">> ");
    scanf_s("%u", &option); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (option == 1) {
        printf("Enter data size >> "); 
        scanf_s("%u", &option); 
        while ((c = getchar()) != '\n' && c != EOF);

        dataBuf = (char*) HeapAlloc(heap, HEAP_ZERO_MEMORY, option); 
        if (dataBuf == NULL) {
            printf("[!] Allocation failed.\n"); 
            return -1; 
        }

        printf("Enter data >> "); 
        fgets(dataBuf, option, stdin); 
        strip_newline(dataBuf); 

        result = RegQueryValueExW(hSubKey, wValue, NULL, &value_type, NULL, NULL); 

        if (result == ERROR_FILE_NOT_FOUND || value_type == REG_SZ) {
            status = RegSetValueExA(hSubKey, value, 0, REG_SZ, (const BYTE *)dataBuf, (DWORD)option);
        } 

        HeapFree(heap, NULL, dataBuf); 
        dataBuf = 0; 

    } else if (option == 2) {
        printf("Enter data >> "); 
        scanf_s("%u", &option); 
        while ((c = getchar()) != '\n' && c != EOF);

        result = RegQueryValueExW(hSubKey, wValue, NULL, &value_type, NULL, NULL); 

        if (result == ERROR_FILE_NOT_FOUND || value_type == REG_DWORD) {
            status = RegSetValueExW(hSubKey, wValue, 0, REG_DWORD, (const BYTE *)&option, sizeof(DWORD)); 
        } 
    } else {
        printf("[!] Invalid option.\n");
        return -1; 
    }

    if (status != ERROR_SUCCESS) {
        printf("\n[!] Modify registry value failed.\n");  
        return -1;
    }

    printf("\n[+] Registry value modified.\n");
    return 0; 
}

int do_ls(wchar_t * dir) {
    int result = 0; 

    wchar_t wSearchPath[MAX_PATH] = {0};
    WIN32_FIND_DATAW file_data;
    HANDLE hSearchHandle; 
    int count = 0; 

    result = swprintf(wSearchPath, MAX_PATH, L"%ls\\*", dir); 
    if (result < 0 || result >= MAX_PATH) {
        printf("[!] An error occurred.\n"); 
        return -1; 
    }

    hSearchHandle = FindFirstFileW(wSearchPath, &file_data);
    if (hSearchHandle == INVALID_HANDLE_VALUE) {
        printf("[!] An error occurred.\n"); 
        return -1;
    }

    count = 0; 

    printf("Directory contents: \n");
    do {
        if (wcscmp(file_data.cFileName, L".") == 0 || wcscmp(file_data.cFileName, L"..") == 0) {
            continue;
        }

        if (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            wprintf(L"[DIRECTORY] %ls\n", file_data.cFileName);
        } else {
            wprintf(L"[FILE]      %ls\n", file_data.cFileName);
        }
        count += 1; 
    } while (FindNextFileW(hSearchHandle, &file_data)); 

    FindClose(hSearchHandle);
    return count; 
}

int check_filename(wchar_t * filename) {
    for (int i = 0; i < 0x10; i++) {
        if (checking_strings[i][0] == '\0') {
            continue; 
        }

        if (wcsstr(filename, checking_strings[i]) != NULL) {
            return 1; 
        }
    }
    return 0; 
}

// CHALLENGE FUNCTIONS
int login() {
    int result = 0; 
    LSTATUS status = 0; 
    HRESULT hr = 0;
    DWORD index = 0; 
    WCHAR wUsername[0x500] = {0}; 
    WCHAR wPassword[0x500] = {0};
    WCHAR wSubkey[0x100] = {0}; 
    WCHAR wValue[0x200] = {0}; 
    DWORD wValueSize = MAX_LEN_PASSWORD;  

    printf("Enter username >> ");
    read_wstr(wUsername, ARRAYSIZE(wUsername)); 
    printf("Enter password >> "); 
    read_wstr(wPassword, ARRAYSIZE(wPassword)); 

    while (1) {
        memset(wSubkey, 0x0, sizeof(wSubkey));
        DWORD subkeyNameLength = ARRAYSIZE(wSubkey);
        status = RegEnumKeyExW(hRoot, index, wSubkey, &subkeyNameLength, NULL, NULL, NULL, NULL
        );

        if (status == ERROR_NO_MORE_ITEMS) {
            wprintf(L"[!] User not found.\n");
            break;
        }

        if (wcscmp(wUsername, wSubkey) == 0) { 
            status = RegGetValueW(hRoot, wSubkey, L"Password", RRF_RT_REG_SZ, NULL, &wValue, &wValueSize); 
            if (status == 0x0) {
                if (wcscmp(wPassword, wValue) == 0) {
                    wprintf(L"[+] Logged in as %ls.\n", wSubkey); 
                    hr = StringCchCopyW(wCurrentUser, ARRAYSIZE(wCurrentUser), wSubkey); 
                    return 1; 
                } else {
                    wprintf(L"[!] Login failed.\n"); 
                    return 0;
                }
            } else { 
                wprintf(L"[!] Login failed.\n"); 
                return 0; 
            }
        } 
        index += 1; 
    }

    return 0; 
}

int create_account(int is_admin) { 
    int c; 
    int result = 0; 
    LSTATUS status = -1; 
    HRESULT hr = -1;
    wchar_t wUsername[0x100] = {0}; 
    wchar_t wBuf[0x500] = {0};
    HKEY hNewUser = NULL; 
    DWORD disposition = 0; 
    unsigned int role = 3; 

    printf("Creating new account...\n"); 

    // New username
    printf("Enter new username >> "); 
    result = read_wstr(wUsername, ARRAYSIZE(wUsername));
    if (result == 0) {
        printf("[!] Account creation failed.\n"); 
        return 0; 
    }

    if (has_invalid_chars(wUsername)) {
        printf("[!] Account creation failed.\n"); 
        return 0; 
    }

    status = RegCreateKeyExW(hRoot, wUsername, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, NULL, &hNewUser, &disposition); 
    if (status != ERROR_SUCCESS) {
        printf("[!] Account creation failed.\n"); 
        return 0; 
    }
    if (disposition == 0x0) { 
        printf("[!] Account creation failed.\n"); 
        return 0; 
    }

    printf("Enter new password >> "); 
    read_wstr(wBuf, ARRAYSIZE(wBuf)); 
    status = RegSetValueExW(hNewUser, L"Password", 0, REG_SZ, (const BYTE *)wBuf, (DWORD)((wcslen(wBuf) + 1) * sizeof(WCHAR))); 
    if (status != ERROR_SUCCESS) {
        goto failure_path;  
    }

    if (is_admin == 1) { 
        printf("Set registry role permissions: \n"); 
        printf("1. Admin\n"); 
        printf("2. Employee\n"); 
        printf("3. Visitor\n"); 
        printf(">> "); 
        scanf_s("%u", &role); 
        while ((c = getchar()) != '\n' && c != EOF);

        if (role < 1 || role > 3) {
            goto failure_path; 
        }
    } 
    status = RegSetValueExW(hNewUser, L"RegistryRole", 0, REG_DWORD, (const BYTE *)&role, sizeof(DWORD)); 
    if (status != ERROR_SUCCESS) {
        goto failure_path;  
    }

    // Set role 
    printf("Enter role >> "); 
    memset(wBuf, 0x0, sizeof(wBuf)); 
    read_wstr(wBuf, ARRAYSIZE(wBuf)); 
    status = RegSetValueExW(hNewUser, L"CompanyRole", 0, REG_SZ, (const BYTE *)&wBuf, (DWORD)((wcslen(wBuf) + 1) * sizeof(WCHAR))); 
    if (status != ERROR_SUCCESS) {
        goto failure_path; 
    }

    // Set note
    printf("Enter note >> "); 
    memset(wBuf, 0x0, sizeof(wBuf)); 
    read_wstr(wBuf, ARRAYSIZE(wBuf)); 
    status = RegSetValueExW(hNewUser, L"Note", 0, REG_SZ, (const BYTE *)&wBuf, (DWORD)((wcslen(wBuf) + 1) * sizeof(WCHAR))); 
    if (status != ERROR_SUCCESS) {
        goto failure_path; 
    }

    // Set home directory
    memset(wBuf, 0x0, sizeof(wBuf)); 
    hr = StringCchCatW(wBuf, ARRAYSIZE(wBuf), ROOTDIR); 
    hr = StringCchCatW(wBuf, ARRAYSIZE(wBuf), wUsername); 
    status = RegSetValueExW(hNewUser, L"DirPath", 0, REG_SZ, (const BYTE *)&wBuf, (DWORD)((wcslen(wBuf) + 1) * sizeof(WCHAR))); 
    if (status != ERROR_SUCCESS) {
        goto failure_path; 
    }

    // Create new home directory
    CreateDirectory(wBuf, NULL);
    wprintf(L"[+] New user %ls created.\n", wUsername);
    status = RegCloseKey(hNewUser);
    hNewUser = NULL; 
    return 1;

failure_path: 
    printf("[!] Account creation failed\n");
    if (hNewUser != NULL) {
        status = RegDeleteTreeW(hNewUser, NULL); 
        status = RegCloseKey(hNewUser); 
        hNewUser = NULL; 
        status = RegDeleteKeyW(hRoot, wUsername); 
    }
    return 0; 
}

int delete_employee() { 
    int c; 
    LSTATUS status = -1; 
    HRESULT hr = -1; 
    DWORD entry_idx = -1; 
    wchar_t wUsername[0x100] = {0}; 
    DWORD usernameLength = ARRAYSIZE(wUsername); 
    wchar_t wBuf[0x500] = {0}; 

    get_employee_username(wUsername, usernameLength); 

    if (wcscmp(wUsername, wCurrentUser) == 0) {
        printf("[!] Cannot delete current user.\n"); 
        return -1; 
    } else if (wcscmp(wUsername, L"Admin") == 0) {
        printf("[!] Cannot delete Admin account.\n"); 
        return -1;
    }

    status = RegDeleteTreeW(hRoot, wUsername); 
    hr = StringCchCatW(wBuf, ARRAYSIZE(wBuf), ROOTDIR); 
    hr = StringCchCatW(wBuf, ARRAYSIZE(wBuf), wUsername); 
    RemoveDirectoryW(wBuf); 

    printf("[+] Deletion successful.\n");

    return 0; 
}

int create_registry(int is_admin) {
    int c; 
    LSTATUS status = -1; 
    HRESULT hr = -1; 
    char buf[0x500] = {0};
    wchar_t wUsername[0x100] = {0}; 
    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD option = 0; 
    HKEY hSubKey = NULL; 
    
    if (is_admin == 1) {
        status = get_employee_username(wUsername, usernameLength);  
        if (status != 0) {
            return -1;
        }
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser);
    }

    printf("Select an option: \n"); 
    printf("1. Registry key\n"); 
    printf("2. Registry value\n"); 
    printf(">> "); 
    scanf_s("%u", &option); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (option == 1) { 
        create_registry_key(wUsername); 
    } else if (option == 2) { 
        hSubKey = get_subkey_handle(wUsername); 
        if (hSubKey == NULL) {
            return -1; 
        }

        modify_registry_value(hSubKey); 
        RegCloseKey(hSubKey); 
        hSubKey = NULL; 
    } else {
        printf("[!] Invalid option\n"); 
        return -1;
    }
    return 0; 
}

int read_registry(int is_admin) {
    LSTATUS status = -1; 
    HRESULT hr = -1; 
    int result = -1; 
    int c; 

    wchar_t wUsername[0x100] = {0}; 
    char value[0x500] = {0}; 
    wchar_t wValue[0x500] = {0}; 
    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD valueLength = ARRAYSIZE(wValue); 
    DWORD dataLength = 0x0; 
    uint16_t calculatedLength = 0x0; 
    char * dataBuf = 0x0; 
    DWORD type = 0; 
    HKEY hUserKey = NULL; 
    HKEY hSubKey = NULL; 
    DWORD max_index = 0; 
    unsigned int option = 0; 

    // Initialize heap
    HANDLE heap = GetProcessHeap(); 
    if (heap == NULL) {
        printf("[!] Heap initialization failed.\n"); 
        return -1; 
    }

    if (is_admin == 1) {
        status = get_employee_username(wUsername, usernameLength);  
        if (status != 0) {
            return -1;
        }
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser);
    }

    status = RegOpenKeyExW(hRoot, wUsername, 0, KEY_ALL_ACCESS, &hUserKey);
    if (status != ERROR_SUCCESS) {
        printf("[!] Subkey open failed\n");
        return -1;
    }

    // Get subkey
    printf("Child registry keys: \n"); 
    enumerate_subkey(hUserKey);
    hSubKey = get_subkey_handle(wUsername); 
    if (hSubKey == NULL) {
        status = RegCloseKey(hUserKey); 
        hUserKey = NULL;
        return -1;
    }

    // Enumerate all values
    printf("Registry values: \n"); 
    max_index = enumerate_values(hSubKey); 

    // Choose one to read
    printf("Name of value to read >> "); 
    fgets(value, sizeof(value), stdin); 
    strip_newline(value); 
    result = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, wValue, ARRAYSIZE(wValue));

    // Get size of data
    status = RegGetValueA(hSubKey, NULL, value, RRF_RT_ANY, &type, NULL, &dataLength); 
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup;
    }
    calculatedLength = dataLength * 2 + 2; 

    // Allocate memory
    dataBuf = (char *) HeapAlloc(heap, HEAP_ZERO_MEMORY, (SIZE_T)calculatedLength); 
    if (dataBuf == NULL) {
        printf("[!] Allocation failed.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Get the data
    dataLength = dataLength * 2 + 2; 
    status = RegGetValueW(hSubKey, NULL, wValue, RRF_RT_ANY, &type, (PVOID)dataBuf, &dataLength);
    dataBuf[dataLength-1] = '\0';
    dataBuf[dataLength-2] = '\0';

    if (type == REG_SZ) {
        wprintf(L"Data: %ls\n", (wchar_t *)dataBuf); 
        result = 0; 
    } else if (type == REG_DWORD) {
        wprintf(L"Data: %u\n", *(int *)dataBuf); 
        result = 0; 
    }

    // Free allocated memory
    HeapFree(heap, NULL, dataBuf); 
    dataBuf = NULL; 

cleanup:
    RegCloseKey(hUserKey); 
    RegCloseKey(hSubKey); 
    hUserKey = NULL; 
    hSubKey = NULL; 

    return result; 
}

int write_registry_admin() {
    HKEY hSubKey = NULL; 
    wchar_t wUsername[0x100] = {0}; 
    DWORD usernameLength = ARRAYSIZE(wUsername); 

    get_employee_username(wUsername, usernameLength); 
    hSubKey = get_subkey_handle(wUsername); 
    if (hSubKey == NULL) {
        return -1; 
    }

    modify_registry_value(hSubKey);
    RegCloseKey(hSubKey); 
    hSubKey = NULL;  

    return 0; 
}

int write_registry_user() {
    int c; 
    LSTATUS status = -1; 
    HRESULT hr = -1; 
    unsigned int option = 0xffffffff; 
    int result = 0; 

    char buf[0x10] = {0}; 
    wchar_t wUsername[0x100] = {0};
    wchar_t wSubKey[0x500] = {0}; 
    wchar_t wBuf[0x100] = {0}; 
    DWORD usernameLength = ARRAYSIZE(wUsername);
    DWORD subkeyLength = ARRAYSIZE(wSubKey);
    HKEY hSubKey = NULL; 

    printf("Current account entries: \n"); 
    enumerate_employees(); 

    printf("Index of account to modify >> "); 
    scanf_s("%u", &option); 
    while ((c = getchar()) != '\n' && c != EOF);

    status = RegEnumKeyExW(hRoot, option, wSubKey, &subkeyLength, NULL, NULL, NULL, NULL); 
    if (status != ERROR_SUCCESS) {
        printf("[!] User not found.\n"); 
        return -1; 
    }

    if (wcscmp(wCurrentUser, wSubKey) == 0) { 
        printf("Use subkey? (y/n) >> "); 
        fgets(buf, 0x10, stdin); 
        strip_newline(buf); 

        memset(wSubKey, 0x0, sizeof(wSubKey));
        subkeyLength = ARRAYSIZE(wSubKey); 
        status = RegEnumKeyExW(hRoot, option, wSubKey, &subkeyLength, NULL, NULL, NULL, NULL);
        result = wcscpy_s(wUsername, usernameLength, wSubKey); 
        if (result != 0x0) {
            printf("[!] An error occurred.\n"); 
            return -1;
        }

        if (strncmp(buf, "y", 1) == 0 || strncmp(buf, "Y", 1) == 0) {
            printf("Enter subkey >> "); 
            result = read_wstr(wBuf, ARRAYSIZE(wBuf)); 
            if (result == 0) {
                printf("[!] An error occurred.\n"); 
                return -1; 
            }

            memset(wSubKey, 0x0, sizeof(wSubKey)); 
            hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), wUsername); 
            hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), L"\\"); 
            hr = StringCchCatW(wSubKey, ARRAYSIZE(wSubKey), wBuf); 

            status = RegOpenKeyExW(hRoot, wSubKey, 0, KEY_ALL_ACCESS, &hSubKey); 
        } else {
            status = RegOpenKeyExW(hRoot, wUsername, 0, KEY_ALL_ACCESS, &hSubKey); 
        }

        if (status != ERROR_SUCCESS) {
            printf("[!] Subkey open failed.\n"); 
            return -1; 
        }

        modify_registry_value(hSubKey); 
        RegCloseKey(hSubKey); 
        hSubKey = NULL; 
        return 0; 
    } else {
        printf("[!] Modification of another account is unauthorized.\n"); 
        return -1; 
    }
}

int delete_registry(int is_admin) {
    int c; 
    LSTATUS status = -1; 
    HRESULT hr = -1; 
    int result = -1;
    
    wchar_t wUsername[0x100] = {0}; 
    wchar_t wBuf[0x500] = {0};
    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD bufLength = ARRAYSIZE(wBuf); 
    HKEY hUserKey = NULL;
    HKEY hSubKey = NULL; 
    DWORD max_index = 0; 
    unsigned int option = 0; 

    if (is_admin == 1) {
        status = get_employee_username(wUsername, usernameLength); 
        if (status != 0) {
            return -1;
        }
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser); 
    }

    status = RegOpenKeyExW(hRoot, wUsername, 0, KEY_ALL_ACCESS, &hUserKey); 

    // Get subkey
    printf("Child registry keys: \n"); 
    enumerate_subkey(hUserKey);
    hSubKey = get_subkey_handle(wUsername); 
    if (hSubKey == NULL) {
        printf("[!] Subkey open failed\n");
        status = RegCloseKey(hUserKey); 
        hUserKey = NULL;
        return -1;
    }

    // Subkey or value
    printf("Delete: \n"); 
    printf("1. Subkey\n"); 
    printf("2. Value\n"); 
    printf(">> "); 
    scanf_s("%u", &option); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (option == 1) { // Subkey
        printf("Child registry keys: \n"); 
        enumerate_subkey(hSubKey);

        printf("Registry key to delete >> "); 
        read_wstr(wBuf, ARRAYSIZE(wBuf));

        status = RegDeleteTreeW(hSubKey, wBuf); 
        if (status != ERROR_SUCCESS) {
            printf("[!] An error occurred.\n"); 
            result = -1; 
            goto cleanup; 
        }
        
        printf("[+] Registry key deleted.\n"); 
        result = 0; 
    
    } else if (option == 2) { // Value
        printf("Registry values: \n"); 
        max_index = enumerate_values(hSubKey); 
    
        printf("Name of value to delete >> "); 
        read_wstr(wBuf, ARRAYSIZE(wBuf));

        status = RegDeleteValueW(hSubKey, wBuf); 
        if (status != ERROR_SUCCESS) {
            printf("[!] An error occurred.\n"); 
            result = -1; 
            goto cleanup; 
        }
        printf("[+] Registry value deleted.\n"); 
        result = 0; 

    } else {
        printf("[!] Invalid option.\n"); 
        result = -1; 
    }

cleanup: 
    RegCloseKey(hUserKey); 
    RegCloseKey(hSubKey); 
    hUserKey = NULL; 
    hSubKey = NULL; 

    return result; 
}

int admin_override(void) {
    int c; 
    LSTATUS status = -1; 
    unsigned int value = 0; 
    unsigned int seed = 0; 
    struct override_data data = {0};  

    // Initialize registry_role
    data.registry_role = 3; 

    printf("Enter reason for override >> "); 
    fgets(data.buf, 0x100, stdin); 
    strip_newline(data.buf); 
    printf("Reason: ");
    printf(data.buf); 
    printf("\n");  

    status = BCryptGenRandom(NULL, (PUCHAR)&value, sizeof(unsigned int), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0x0) {
        printf("[!] Generation failed\n"); 
        return 3; 
    }

    seed = value & 0xff; 
    srand(seed); 
    value = rand(); 
    
    seed = 0; 
    printf("Enter the override code >> "); 
    scanf_s("%u", &seed); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (seed == value) { 
        StringCchCopyW(wCurrentUser, ARRAYSIZE(wCurrentUser), L"Admin"); 
        data.registry_role = 1;
        return data.registry_role; 
    } else { 
        return data.registry_role; 
    }
}

int create_file(int is_admin) {
    int c; 
    int option = 0; 
    LSTATUS status = 0; 
    HRESULT hr = 0; 
    int result = 0; 

    HKEY hUserKey = NULL; 
    WCHAR wUsername[0x100] = {0}; 
    WCHAR wUserDir[MAX_PATH] = {0}; 
    WCHAR wFileName[0x100] = {0}; 
    WCHAR wFullFilePath[MAX_PATH] = {0}; 
    WCHAR wData[MAX_PATH] = {0}; 

    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD userdirLength = ARRAYSIZE(wUserDir); 
    DWORD filenameLength = ARRAYSIZE(wFileName); 
    DWORD dataLength = ARRAYSIZE(wData);

    HANDLE obj = NULL; 

    if (is_admin == 1) {
        get_employee_username(wUsername, usernameLength);  
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser); 
    }

    status = RegOpenKeyExW(hRoot, (LPCWSTR)wUsername, 0, KEY_ALL_ACCESS, &hUserKey);
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        return -1; 
    }

    status = RegGetValueW(hRoot, wUsername, L"DirPath", RRF_RT_REG_SZ, NULL, &wUserDir, &userdirLength); 
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup; 
    }

    printf("File type to be created: \n"); 
    printf("1. File\n"); 
    printf("2. Directory\n");
    printf("3. Symlink\n"); 
    printf("4. Junction\n"); 
    printf(">> "); 
    scanf_s("%u", &option); 
    while ((c = getchar()) != '\n' && c != EOF); 

    printf("Enter desired filename >> "); 
    read_wstr(wFileName, 0x100); 
    
    result = check_filename(wFileName); 
    if (result == 1) {
        printf("[!] Invalid sequence in filename.\n"); 
        result = -1; 
        goto cleanup; 
    }

    hr = StringCchCatW(wFullFilePath, ARRAYSIZE(wFullFilePath), wUserDir); 
    hr = StringCchCatW(wFullFilePath, ARRAYSIZE(wFullFilePath), L"\\"); 
    hr = StringCchCatW(wFullFilePath, ARRAYSIZE(wFullFilePath), wFileName); 

    switch (option) {
        case 1: // File
            obj = CreateFileW(wFullFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 
            if (obj == INVALID_HANDLE_VALUE) {
                printf("[!] An error occurred.\n"); 
                result = -1;
            } else {
                printf("[+] File created successfully.\n"); 
                result = 0;
            }
            goto cleanup; 
            break; 
        case 2: // Directory
            if (!CreateDirectoryW(wFullFilePath, NULL)) {
                printf("[!] An error occurred.\n");
                result = 1;  
            } else {
                printf("[+] New directory created.\n");
                result = 0;  
            }
            goto cleanup; 
            break; 
        case 3: // Symlink 
            memset(wFileName, 0x0, sizeof(wFileName)); 
            printf("Enter symlink target >> "); 
            read_wstr(wFileName, sizeof(wFileName));
            
            // Do checks
            result = check_filename(wFileName); 
            if (result == 1) {
                printf("[!] Invalid sequence in filename.\n"); 
                result = -1; 
                goto cleanup; 
            }

            // Concatenate filename
            hr = StringCchCatW(wData, ARRAYSIZE(wData), wUserDir); 
            hr = StringCchCatW(wData, ARRAYSIZE(wData), L"\\"); 
            hr = StringCchCatW(wData, ARRAYSIZE(wData), wFileName); 

            // Create symlink
            result = CreateSymbolicLinkW(wFullFilePath, wData, 0x0 | 0x2); 
            if (result != 0x0) {
                printf("[+] Symlink created.\n"); 
                result = 0; 
            } else {
                printf("[!] An error occurred.\n"); 
                result = -1; 
            }
            goto cleanup; 

            break; 
        case 4: // Junction
            memset(wFileName, 0x0, sizeof(wFileName)); 
            printf("Enter junction target >> "); 
            read_wstr(wFileName, sizeof(wFileName));
            
            // Do checks
            result = check_filename(wFileName); 
            if (result == 1) {
                printf("[!] Invalid sequence in directory name.\n"); 
                result = -1; 
                goto cleanup; 
            }

            // Concatenate filename
            hr = StringCchCatW(wData, ARRAYSIZE(wData), wUserDir); 
            hr = StringCchCatW(wData, ARRAYSIZE(wData), L"\\"); 
            hr = StringCchCatW(wData, ARRAYSIZE(wData), wFileName); 

            // Create symlink
            result = CreateSymbolicLinkW(wFullFilePath, wData, 0x1 | 0x2); 
            if (result != 0x0) {
                printf("[+] Symlink created.\n"); 
                result = 0; 
            } else {
                printf("[!] An error occurred.\n"); 
                result = -1; 
            }
            goto cleanup; 
            break; 
        default: 
            printf("[!] Illegal option!\n"); 
            result = -1; 
            goto cleanup; 
    }

cleanup: 
    if (hUserKey != NULL) {
        RegCloseKey(hUserKey); 
        hUserKey = NULL; 
    }
    if (obj != NULL) {
        CloseHandle(obj); 
        obj = NULL; 
    }
    return result; 
}

int read_file(int is_admin) {
    LSTATUS status = 0;
    int result = 0; 
    HRESULT hr = 0; 

    HKEY hUserKey = NULL; 
    WCHAR wUsername[0x100] = {0}; 
    WCHAR wUserDir[MAX_PATH] = {0};
    WCHAR wFileName[0x100] = {0}; 
    WCHAR wFullPath[MAX_PATH] = {0}; 

    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD userdirLength = ARRAYSIZE(wUserDir); 
    DWORD fullpathLength = ARRAYSIZE(wFullPath); 

    HANDLE file = NULL; 
    BYTE buffer[4096] = {0}; 
    DWORD bytes_read;

    if (is_admin == 1) {
        get_employee_username(wUsername, usernameLength);  
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser); 
    }

    status = RegOpenKeyExW(hRoot, (LPCWSTR)wUsername, 0, KEY_ALL_ACCESS, &hUserKey);
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        return -1; 
    }

    status = RegGetValueW(hRoot, wUsername, L"DirPath", RRF_RT_REG_SZ, NULL, &wUserDir, &userdirLength); 
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup; 
    }

    result = do_ls(wUserDir); 
    if (result < 1) {
        printf("[!] No files in directory.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Get file to read
    printf("Enter desired filename >> "); 
    read_wstr(wFileName, 0x100); 
    
    // Check filename
    result = check_filename(wFileName); 
    if (result == 1) {
        printf("[!] Invalid sequence in filename.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Concatenate filename
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wUserDir); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), L"\\"); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wFileName); 

    // Open file
    file = CreateFileW(wFullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup;
    }

    // Read file
    for (;;) {
        BOOL ok = ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL);
        if (!ok) {
            printf("[!] Read error.\n"); 
            result = -1; 
            goto cleanup;
        }

        if (bytes_read == 0) {
            printf("[+] Read complete.\n"); 
            result = 0; 
            break; 
        }

        DWORD bytes_written;
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);

        if (!WriteFile(output, buffer, bytes_read, &bytes_written, NULL)) {
            printf("[!] Write error.\n"); 
            result = -1; 
            goto cleanup; 
        }
    }

cleanup: 
    if (hUserKey != NULL) {
        RegCloseKey(hUserKey); 
        hUserKey = NULL; 
    }
    if (file != NULL) {
        CloseHandle(file); 
        file = NULL; 
    }
    return result; 
}

int write_file(int is_admin) {
    LSTATUS status = 0;
    int result = 0; 
    HRESULT hr = 0; 
    int c; 

    HKEY hUserKey = NULL; 
    WCHAR wUsername[0x100] = {0}; 
    WCHAR wUserDir[MAX_PATH] = {0};
    WCHAR wFileName[0x100] = {0}; 
    WCHAR wFullPath[MAX_PATH] = {0}; 

    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD userdirLength = ARRAYSIZE(wUserDir); 
    DWORD fullpathLength = ARRAYSIZE(wFullPath); 

    HANDLE file = NULL; 
    DWORD data_size = 0; 
    char * data = 0; 
    const BYTE *p; 
    DWORD remaining; 

    // Initialize heap 
    HANDLE heap = GetProcessHeap(); 
    if (heap == NULL) {
        printf("[!] Heap initialization failed.\n"); 
        result = -1; 
        goto cleanup; 
    }

    if (is_admin == 1) {
        get_employee_username(wUsername, usernameLength);  
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser); 
    }

    status = RegOpenKeyExW(hRoot, (LPCWSTR)wUsername, 0, KEY_ALL_ACCESS, &hUserKey);
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        return -1; 
    }

    // Get the home directory of the user
    status = RegGetValueW(hRoot, wUsername, L"DirPath", RRF_RT_REG_SZ, NULL, &wUserDir, &userdirLength); 
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup; 
    }

    result = do_ls(wUserDir); 
    if (result < 1) {
        printf("[!] No files in directory.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Get file to read
    printf("Enter desired filename >> "); 
    read_wstr(wFileName, 0x100); 
    
    // Check filename
    result = check_filename(wFileName); 
    if (result == 1) {
        printf("[!] Invalid sequence in filename.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Concatenate filename
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wUserDir); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), L"\\"); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wFileName); 

    // Open file
    file = CreateFileW(wFullPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup;
    }

    // Obtain data
    printf("Size of data >> "); 
    scanf_s("%u", &data_size); 
    while ((c = getchar()) != '\n' && c != EOF);

    // Allocate memory
    data = (char*) HeapAlloc(heap, HEAP_ZERO_MEMORY, data_size); 
    if (data == NULL) {
        printf("[!] Allocation failed.\n"); 
        return -1; 
    }

    // Get data
    printf("Enter data >> "); 
    fgets(data, data_size, stdin); 

    // Write to file
    p = (const BYTE *)data;
    remaining = data_size;

    while (remaining != 0) {
        DWORD written = 0;
        if (!WriteFile(file, p, remaining, &written, NULL) || written == 0) {
            printf("[!] Write error\n"); 
            result = -1; 
            goto cleanup; 
        }

        p += written;
        remaining -= written;
    }

    if (!SetEndOfFile(file)) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup; 
    }

    printf("[+] File write complete.\n");
    result = 0; 

cleanup: 
    if (hUserKey != NULL) {
        RegCloseKey(hUserKey); 
        hUserKey = NULL; 
    }
    if (file != NULL) {
        CloseHandle(file); 
        file = NULL; 
    }
    if (data != 0x0) {
        HeapFree(heap, NULL, data); 
        data = 0; 
    }
    return result; 
}

int delete_file(int is_admin) {
    LSTATUS status = 0; 
    int result = 0; 
    HRESULT hr = 0; 

    HKEY hUserKey = NULL; 
    WCHAR wUsername[0x100] = {0}; 
    WCHAR wUserDir[MAX_PATH] = {0};
    WCHAR wFileName[0x100] = {0}; 
    WCHAR wFullPath[MAX_PATH] = {0}; 

    DWORD usernameLength = ARRAYSIZE(wUsername); 
    DWORD userdirLength = ARRAYSIZE(wUserDir); 
    DWORD fullpathLength = ARRAYSIZE(wFullPath); 

    HANDLE obj = NULL; 
    DWORD attributes = 0; 

    if (is_admin == 1) {
        get_employee_username(wUsername, usernameLength);  
    } else {
        hr = StringCchCopyW(wUsername, ARRAYSIZE(wUsername), wCurrentUser); 
    }

    status = RegOpenKeyExW(hRoot, (LPCWSTR)wUsername, 0, KEY_ALL_ACCESS, &hUserKey);
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        return -1; 
    }

    // Get the home directory of the user
    status = RegGetValueW(hRoot, wUsername, L"DirPath", RRF_RT_REG_SZ, NULL, &wUserDir, &userdirLength); 
    if (status != ERROR_SUCCESS) {
        printf("[!] An error occurred.\n"); 
        result = -1; 
        goto cleanup; 
    }

    result = do_ls(wUserDir); 
    if (result < 1) {
        printf("[!] No files in directory.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Get file to read
    printf("Enter desired filename >> "); 
    read_wstr(wFileName, 0x100); 
    
    // Check filename
    result = check_filename(wFileName); 
    if (result == 1) {
        printf("[!] Invalid sequence in filename.\n"); 
        result = -1; 
        goto cleanup; 
    }

    // Concatenate filename
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wUserDir); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), L"\\"); 
    hr = StringCchCatW(wFullPath, ARRAYSIZE(wFullPath), wFileName);

    attributes = GetFileAttributesW(wFullPath);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        printf("[!] An error occurred.\n");
        result = -1; 
        goto cleanup; 
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        RemoveDirectoryW(wFullPath);
        result = 0; 
    } else {
        DeleteFileW(wFullPath);
        result = 0; 
    }

    printf("[+] Deletion successful.\n"); 

cleanup: 
    if (hUserKey != NULL) {
        RegCloseKey(hUserKey); 
        hUserKey = NULL; 
    }
    return result; 
}

int store_note() {
    int c;
    int size = 0; 
    char * buf = NULL; 

    HANDLE heap = GetProcessHeap(); 
    if (heap == NULL) {
        printf("[!] Heap initialization failed.\n"); 
        return -1; 
    }

    if (NoteIdx >= MAX_NOTE) {
        printf("[!] Maximum number of notes reached.\n"); 
        return -1; 
    }

    // Get data size
    printf("Enter data size >> "); 
    scanf_s("%u", &size); 
    while ((c = getchar()) != '\n' && c != EOF);

    // Allocate memory
    buf = (char*) HeapAlloc(heap, HEAP_ZERO_MEMORY, size); 
    if (buf == NULL) {
        printf("[!] Allocation failed.\n"); 
        return -1; 
    }

    // Store data
    printf("Enter data >> "); 
    fgets(buf, size, stdin); 

    Notes[NoteIdx] = buf; 
    NoteSize[NoteIdx] = size; 
    NoteIdx += 1; 
    printf("[+] Note creation successful.\n"); 

    return 0; 
}

int read_note() {
    unsigned int idx = 0; 
    char * buf = 0; 
    int c; 

    printf("Enter idx >> "); 
    scanf_s("%u", &idx); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (idx >= NoteIdx || idx >= MAX_NOTE) {
        printf("[!] Invalid idx.\n"); 
        return -1; 
    }

    buf = Notes[idx]; 
    if (buf != 0x0) {
        puts(buf); 
    } else {
        printf("[!] Note slot is empty.\n"); 
    }

    return 0; 
}

int delete_note() {
    int c; 
    unsigned int idx = 0; 
    char * buf = 0; 

    HANDLE heap = GetProcessHeap(); 
    if (heap == NULL) {
        printf("[!] Heap initialization failed.\n"); 
        return -1; 
    }

    printf("Enter idx >> "); 
    scanf_s("%u", &idx); 
    while ((c = getchar()) != '\n' && c != EOF);

    if (idx >= NoteIdx || idx >= MAX_NOTE ) {
        printf("[!] Invalid idx.\n"); 
        return -1;
    }

    buf = Notes[idx]; 
    if (buf != 0x0) {
        HeapFree(heap, NULL, buf); 
        buf = 0x0; 
        Notes[idx] = 0x0; 
        printf("[+] Free successful.\n"); 
    } else {
        printf("[!] Note slot is empty.\n"); 
    }

    return 0; 
}

// MAIN FUNCTION
int main(void) {
    // Flags
    unsigned int exit_flag = 0; 
    unsigned int acc_create_flag = 0; 
    unsigned int login_flag = 0; 
    unsigned int registry_role = 3; 

    // Variables
    int c;
    unsigned int opcode = 0; 
    int ret = -1; 
    DWORD registry_role_size = sizeof(registry_role); 
    LSTATUS status = -1; 

    // Setup
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Open root registry key
    status = RegOpenKeyExW(HKEY_CURRENT_USER, L"SOLIS", 0, KEY_ALL_ACCESS, &hRoot);

    // Print banner
    print_banner();
    
    while (exit_flag == 0) {
        print_menu(); 
        scanf_s("%u", &opcode); 
        while ((c = getchar()) != '\n' && c != EOF);
        
        switch(opcode) {
            case 1: // Login
                if (login_flag == 0) {
                    login_flag = login(); 

                    // Update registry role
                    status = RegGetValueW(hRoot, wCurrentUser, L"RegistryRole", RRF_RT_REG_DWORD, NULL, (PVOID)&registry_role, &registry_role_size); 

                } else {
                    wprintf(L"[!] Already logged in as %ls.\n", wCurrentUser); 
                }
                break;
            case 2: // View all employees
                enumerate_employees(); 
                break;
            case 3: // Create account
                if (login_flag == 0 && acc_create_flag == 0) {
                    acc_create_flag = create_account(0); 
                } else if (registry_role == 1) { // Admin
                    create_account(1); 
                } else {
                    printf("[!] You cannot create an account at this time.\n");
                }
                break;
            case 4: // Delete employee
                if ((login_flag == 1) && (registry_role == 1)) {
                    delete_employee(); 
                } else {
                    printf("[!] Unauthorized to perform delete operation.\n"); 
                }
                break;
            case 5: // Create key/value
                if (login_flag == 1 && registry_role == 1) {
                    create_registry(1);
                } else if (login_flag == 1) {
                    create_registry(0); 
                } else {
                    printf("[!] Unauthorized to perform create operation.\n");
                }
                break; 
            case 6: // Read key/value
                if (login_flag == 1 && registry_role == 1) {
                    read_registry(1); 
                } else if (login_flag == 1) {
                    read_registry(0); 
                } else {
                    printf("[!] Unauthorized to perform read operation.\n"); 
                }
                break; 
            case 7: // Write value 
                if (login_flag == 1 && registry_role == 1) {
                    write_registry_admin(); 
                } else if (login_flag == 1) {
                    write_registry_user();
                } else {
                    printf("[!] Unauthorized to perform write operation.\n"); 
                }
                break;
            case 8: // Delete key/value
                if (login_flag == 1 && registry_role == 1) {
                    delete_registry(1); 
                } else if (login_flag == 1) {
                    delete_registry(0); 
                } else {
                    printf("[!] Unauthorized to perform delete operation.\n"); 
                }
                break; 
            case 9: // Create file
                if (login_flag == 1 && registry_role == 1) {
                    create_file(1); 
                } else if (login_flag == 1) {
                    create_file(0); 
                } else {
                    printf("[!] Unauthorized to perform create operation.\n");
                }
                break;
            case 10: // Read file
                if (login_flag == 1 && registry_role == 1) {
                    read_file(1); 
                } else if (login_flag == 1) {
                    read_file(0); 
                } else {
                    printf("[!] Unauthorized to perform read operation.\n"); 
                }
                break; 
            case 11: // Write file 
                if (login_flag == 1 && registry_role == 1) {
                    write_file(1); 
                } else if (login_flag == 1) {
                    write_file(0); 
                } else {
                    printf("[!] Unauthorized to perform write operation.\n");
                }
                break; 
            case 12: // Delete file 
                if (login_flag == 1 && registry_role == 1) {
                    delete_file(1); 
                } else if (login_flag == 1) {
                    delete_file(0);
                } else {
                    printf("[!] Unauthorized to perform delete operation.\n"); 
                }
                break; 
            case 13: // Logout
                if (login_flag == 1) {
                    memset(wCurrentUser, 0x0, sizeof(wCurrentUser)); 
                    login_flag = 0; 
                    registry_role = 3; 
                    printf("[+] Successfully logged out.\n"); 
                } else {
                    printf("[!] You are not logged in.\n");
                }
                break; 
            case 14: // Store note
                store_note(); 
                break; 
            case 15: // Read note
                read_note();
                break; 
            case 16: // Delete note
                delete_note(); 
                break; 
            case 17: // Admin override 
                registry_role = admin_override(); 
                if (registry_role == 1) {
                    login_flag = 1; 
                    printf("[+] Override success!\n"); 
                } else {
                    printf("[!] Override failed.\n"); 
                }
                break; 
            case 18: // Exit
                exit_flag = 1; 
                printf("Goodbye!");
                break; 
            default: 
                printf("Invalid option!\n");
        }
    }

    return 0; 
}
