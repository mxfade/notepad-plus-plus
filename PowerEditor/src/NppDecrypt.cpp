#include "Notepad_plus.h"
#include "Notepad_plus_Window.h"
#include "resource.h"
#include "menuCmdID.h"
#include "ScintillaComponent/ScintillaEditView.h"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <string>

// Default password as requested
static const wchar_t* DEFAULT_DECRYPT_PASSWORD = L"7@yiZxbzZ3kX+t+T_vdpV2_vo@yL6k#C";

static std::vector<uint8_t> Base64DecodeWide(const std::wstring& src)
{
	std::vector<uint8_t> out;
	DWORD needed = 0;
	if (!CryptStringToBinaryW(src.c_str(), 0, CRYPT_STRING_BASE64, NULL, &needed, NULL, NULL))
		return out;
	out.resize(needed);
	if (!CryptStringToBinaryW(src.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &needed, NULL, NULL))
	{
		out.clear();
	}
	return out;
}

// Convert std::wstring (UTF-16) to UTF-8 bytes
static std::string WideToUtf8(const std::wstring& w)
{
	if (w.empty()) return {};
	int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
	std::string out(size, '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), size, nullptr, nullptr);
	return out;
}

// Convert UTF-8 bytes to wide string
static std::wstring Utf8ToWide(const char* data, size_t len)
{
	if (!data || len == 0) return {};
	int size = MultiByteToWideChar(CP_UTF8, 0, data, (int)len, nullptr, 0);
	std::wstring out(size, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, data, (int)len, out.data(), size);
	return out;
}

// Convert bytes to uppercase hex string
static std::wstring BytesToHex(const uint8_t* data, size_t len)
{
	if (!data || len == 0) return {};
	std::wstring out;
	out.reserve(len * 2);
	wchar_t buf[8];
	for (size_t i = 0; i < len; ++i)
	{
		swprintf(buf, ARRAYSIZE(buf), L"%02X", data[i]);
		out.append(buf);
	}
	return out;
}

// Create AES key blob and import to CryptProv
static HCRYPTKEY ImportAesKey(HCRYPTPROV hProv, const std::vector<uint8_t>& key)
{
	if (key.empty()) return 0;
	// Determine algorithm
	ALG_ID alg = 0;
	if (key.size() == 16) alg = CALG_AES_128;
	else if (key.size() == 24) alg = CALG_AES_192;
	else if (key.size() == 32) alg = CALG_AES_256;
	else return 0; // unsupported key length

	// Build PLAINTEXTKEYBLOB: BLOBHEADER + DWORD cbKey + key bytes
	DWORD blobLen = sizeof(BLOBHEADER) + sizeof(DWORD) + (DWORD)key.size();
	std::vector<uint8_t> blob(blobLen);
	BLOBHEADER* pbh = reinterpret_cast<BLOBHEADER*>(blob.data());
	pbh->bType = PLAINTEXTKEYBLOB;
	pbh->bVersion = CUR_BLOB_VERSION;
	pbh->reserved = 0;
	pbh->aiKeyAlg = alg;
	DWORD* pcb = reinterpret_cast<DWORD*>(blob.data() + sizeof(BLOBHEADER));
	*pcb = (DWORD)key.size();
	uint8_t* pKeyData = blob.data() + sizeof(BLOBHEADER) + sizeof(DWORD);
	memcpy(pKeyData, key.data(), key.size());

	HCRYPTKEY hKey = 0;
	if (!CryptImportKey(hProv, blob.data(), blobLen, 0, 0, &hKey))
		return 0;
	return hKey;
}

// Get AES key bytes same as C# GetAesKey
static std::vector<uint8_t> GetAesKeyFromPassword(const std::wstring& password)
{
	std::string utf8 = WideToUtf8(password);
	std::vector<uint8_t> bytes(utf8.begin(), utf8.end());
	if (bytes.size() < 16)
		bytes.resize(16, 0);
	else if (bytes.size() > 32)
		bytes.resize(32);
	// If length is between 17 and 31, try to keep; CryptImportKey supports 16/24/32 only.
	if (bytes.size() != 16 && bytes.size() != 24 && bytes.size() != 32)
	{
		// adjust to nearest supported: prefer 32 if >16
		if (bytes.size() > 16) bytes.resize(32, 0);
		else bytes.resize(16, 0);
	}
	return bytes;
}

// Base64 encode helper
static std::wstring Base64EncodeWide(const uint8_t* data, size_t len)
{
	std::wstring out;
	if (!data || len == 0) return out;
	DWORD needed = 0;
	if (!CryptBinaryToStringW(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &needed))
		return out;
	out.resize(needed);
	if (!CryptBinaryToStringW(data, (DWORD)len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &needed))
		return L"";
	if (!out.empty() && out.back() == L'\0') out.pop_back();
	return out;
}

// Encrypt current document per-line (log style): produce Base64 of IV(16)|cipher per line and open new document
void Notepad_plus::encryptLogFile()
{
	std::wstring password = DEFAULT_DECRYPT_PASSWORD;

	ScintillaEditView* pView = _pEditView;
	if (!pView) return;

	size_t docLen = pView->getCurrentDocLen();
	std::wstring text = pView->getGenericTextAsString(0, docLen);

	std::wstring newTabName = L"decrypted";
	const wchar_t* fn_name = pView->getCurrentBuffer()->getFileName();
	if (fn_name && fn_name[0] != L'\0')
	{
		std::wstring base(fn_name);
		// extract file name and extension using string operations (avoids <filesystem> dependency)
		newTabName = base;
	}
	// split lines
	// prepare crypto
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;

	std::vector<uint8_t> key = GetAesKeyFromPassword(password);
	HCRYPTKEY hKey = ImportAesKey(hProv, key);
	if (!hKey) { CryptReleaseContext(hProv, 0); return; }

	std::wstring outW;
	// split lines
	size_t start = 0;
	while (start < text.size())
	{
		size_t pos = text.find_first_of(L"\r\n", start);
		std::wstring ln;
		if (pos == std::wstring::npos) { ln = text.substr(start); start = text.size(); }
		else { ln = text.substr(start, pos - start); size_t n = 1; if (text[pos] == L'\r' && pos + 1 < text.size() && text[pos+1] == L'\n') n = 2; start = pos + n; }

		std::wstring trimmed = ln;
		while (!trimmed.empty() && iswspace(trimmed.back())) trimmed.pop_back();
		size_t idx = 0; while (idx < trimmed.size() && iswspace(trimmed[idx])) idx++; if (idx) trimmed.erase(0, idx);
		if (trimmed.empty()) { outW.push_back(L'\n'); continue; }

		std::string plainUtf8 = WideToUtf8(trimmed);
		DWORD plainLen = (DWORD)plainUtf8.size();

		BYTE iv[16] = {0};
		if (!CryptGenRandom(hProv, 16, iv)) memset(iv, 0, 16);

		if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) { outW.append(ln); outW.push_back(L'\n'); continue; }

		DWORD bufLen = plainLen + 16;
		std::vector<BYTE> buf(bufLen);
		memcpy(buf.data(), plainUtf8.data(), plainLen);
		DWORD dwLen = plainLen;
		if (!CryptEncrypt(hKey, 0, TRUE, 0, buf.data(), &dwLen, bufLen)) { outW.append(ln); outW.push_back(L'\n'); continue; }

		std::vector<BYTE> combined(16 + dwLen);
		memcpy(combined.data(), iv, 16);
		memcpy(combined.data() + 16, buf.data(), dwLen);

		std::wstring b64 = Base64EncodeWide(combined.data(), combined.size());
		outW.append(b64);
		outW.push_back(L'\n');
	}

	fileNew();
	ScintillaEditView* pViewNew = _pEditView;
	if (pViewNew)
	{
		std::string outUtf8 = WideToUtf8(outW);
		pViewNew->execute(SCI_SETTEXT, 0, reinterpret_cast<LPARAM>(outUtf8.c_str()));
	}

	fileRenameUntitledPluginAPI(BUFFER_INVALID, newTabName.c_str());
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
}

// Encrypt current document as config (binary) and overwrite file on disk (requires saved file)
void Notepad_plus::encryptConfigFile()
{
	std::wstring password = DEFAULT_DECRYPT_PASSWORD;

	const wchar_t* fullPath = nullptr;
	if (_pEditView && _pEditView->getCurrentBuffer()) fullPath = _pEditView->getCurrentBuffer()->getFullPathName();
	if (!fullPath || fullPath[0] == L'\0') { MessageBoxW(_pPublicInterface->getHSelf(), L"当前文档未保存到磁盘，无法按文件字节加密。请先保存文件。", L"无法加密", MB_ICONWARNING); return; }

	ScintillaEditView* pView = _pEditView; if (!pView) return;
	size_t docLen = pView->getCurrentDocLen(); std::wstring text = pView->getGenericTextAsString(0, docLen);
	std::string plainUtf8 = WideToUtf8(text);

	// prepare a name for the new tab that will display the encrypted payload
	std::wstring newTabName = L"encrypted";
	const wchar_t* fn_name = pView->getCurrentBuffer()->getFileName();
	if (fn_name && fn_name[0] != L'\0')
	{
		std::wstring base(fn_name);
		newTabName = base;
	}

	std::vector<uint8_t> key = GetAesKeyFromPassword(password);
	BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!BCRYPT_SUCCESS(status)) return;
	status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
	if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); return; }
	status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
	if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); return; }

	ULONG cbOutput = 0;
	status = BCryptEncrypt(hKey, (PUCHAR)plainUtf8.data(), (ULONG)plainUtf8.size(), NULL, NULL, 0, NULL, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
	if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg,0); return; }
	std::vector<BYTE> cipher(cbOutput);
	status = BCryptEncrypt(hKey, (PUCHAR)plainUtf8.data(), (ULONG)plainUtf8.size(), NULL, NULL, 0, cipher.data(), cbOutput, &cbOutput, BCRYPT_BLOCK_PADDING);
	if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg,0); return; }
	cipher.resize(cbOutput);

	std::wstring outW;
	outW.append(L"ENCRYPTEDv1:");
	if (!cipher.empty())
	{
	
		outW.reserve(outW.size() + cipher.size());
		for (size_t i = 0; i < cipher.size(); ++i)
			outW.push_back(static_cast<wchar_t>(cipher[i]));
	}

	fileNew();
	ScintillaEditView* pViewNew = _pEditView;
	if (pViewNew)
	{
		std::string outUtf8 = WideToUtf8(outW);
		pViewNew->execute(SCI_SETTEXT, 0, reinterpret_cast<LPARAM>(outUtf8.c_str()));
	}

	fileRenameUntitledPluginAPI(BUFFER_INVALID, newTabName.c_str());

	BCryptDestroyKey(hKey); 
	BCryptCloseAlgorithmProvider(hAlg,0);
}

// Auto-detect and encrypt: use log method for .log, otherwise config method
void Notepad_plus::encryptAuto()
{
	const wchar_t* fn_name = nullptr;
	if (_pEditView && _pEditView->getCurrentBuffer()) fn_name = _pEditView->getCurrentBuffer()->getFileName();
	std::wstring filename = fn_name ? fn_name : L"";
	size_t sep = filename.find_last_of(L"\\/"); if (sep != std::wstring::npos) filename = filename.substr(sep + 1);
	size_t pos = filename.find_last_of(L'.'); std::wstring ext = (pos == std::wstring::npos) ? L"" : filename.substr(pos);
	for (auto &c : ext) c = towlower(c);
	if (ext == L".log") encryptLogFile(); else encryptConfigFile();
}

// Auto-detect encrypted file type and dispatch to appropriate decrypt method. (patched)
void Notepad_plus::decryptAuto()
{
	const char* magic = "ENCRYPTEDv1:";
	size_t magicLen = strlen(magic);
	bool hasMagic = false;

	// Try to read from saved file on disk first
	const wchar_t* fullPath = nullptr;
	if (_pEditView && _pEditView->getCurrentBuffer())
		fullPath = _pEditView->getCurrentBuffer()->getFullPathName();

	if (fullPath && fullPath[0] != L'\0')
	{
		HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD toRead = (DWORD)magicLen;
			std::vector<char> buf(toRead);
			DWORD read = 0;
			if (ReadFile(hFile, buf.data(), toRead, &read, NULL) && read >= (DWORD)magicLen)
			{
				if (memcmp(buf.data(), magic, magicLen) == 0)
					hasMagic = true;
			}
			CloseHandle(hFile);
		}
	}

	// If not available on disk, inspect in-memory text start
	if (!hasMagic)
	{
		ScintillaEditView* pView = _pEditView;
		if (pView)
		{
			size_t docLen = pView->getCurrentDocLen();
			size_t checkLen = docLen < magicLen ? docLen : magicLen;
			if (checkLen >= 1)
			{
				std::wstring start = pView->getGenericTextAsString(0, checkLen);
				const wchar_t* magicW = L"ENCRYPTEDv1:";
				size_t magicWLen = wcslen(magicW);
				if (start.size() >= magicWLen && start.compare(0, magicWLen, magicW) == 0)
					hasMagic = true;
			}
		}
	}

	if (hasMagic)
		decryptConfigFile();
	else
		decryptFile();
}

void Notepad_plus::decryptEncryptedJsonXml(BufferID buffer)
{
	if (!buffer)
		return;

	const wchar_t* fileName = buffer->getFileName();
	if (!fileName || fileName[0] == L'\0')
		return;

	const wchar_t* extension = wcsrchr(fileName, L'.');
	if (!extension || (_wcsicmp(extension, L".json") != 0 && _wcsicmp(extension, L".xml") != 0))
		return;

	const wchar_t* fullPath = buffer->getFullPathName();
	if (!fullPath || fullPath[0] == L'\0')
		return;

	static constexpr char encryptedMagic[] = "ENCRYPTEDv1:";
	HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	char header[sizeof(encryptedMagic) - 1]{};
	DWORD bytesRead = 0;
	const bool hasMagic = ReadFile(hFile, header, sizeof(header), &bytesRead, nullptr)
		&& bytesRead == sizeof(header)
		&& memcmp(header, encryptedMagic, sizeof(header)) == 0;
	CloseHandle(hFile);

	if (hasMagic)
	{
		activateBuffer(buffer, currentView());
		decryptConfigFile(fullPath);
	}
}


void Notepad_plus::decryptFile()
{
	std::wstring password = DEFAULT_DECRYPT_PASSWORD;

	// get current view
	ScintillaEditView* pView = _pEditView;
	if (!pView) return;

	size_t docLen = pView->getCurrentDocLen();
	std::wstring text = pView->getGenericTextAsString(0, docLen);

	std::wstring newTabName = L"decrypted";
	const wchar_t* fn_name = pView->getCurrentBuffer()->getFileName();
	if (fn_name && fn_name[0] != L'\0')
	{
		std::wstring base(fn_name);
		// extract file name and extension using string operations (avoids <filesystem> dependency)
		std::wstring filename = base;
		// remove any path components if present
		size_t sep = filename.find_last_of(L"\\/");
		if (sep != std::wstring::npos) filename = filename.substr(sep + 1);
		size_t pos = filename.find_last_of(L'.');
		if (pos == std::wstring::npos || pos == 0)
			newTabName = filename + L"_解密"; // no extension found
		else
			newTabName = filename.substr(0, pos) + L"_解密" + filename.substr(pos);
	}
	// split lines
	std::vector<std::wstring> lines;
	size_t start = 0;
	while (start < text.size())
	{
		size_t pos = text.find_first_of(L"\r\n", start);
		if (pos == std::wstring::npos)
		{
			lines.push_back(text.substr(start));
			break;
		}
		if (pos > start)
			lines.push_back(text.substr(start, pos - start));
		// skip CRLF sequence
		size_t n = 1;
		if (text[pos] == L'\r' && pos + 1 < text.size() && text[pos+1] == L'\n') n = 2;
		start = pos + n;
	}

	// prepare crypto
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		// failed
		return;
	}

	std::vector<uint8_t> key = GetAesKeyFromPassword(password);
	HCRYPTKEY hKey = ImportAesKey(hProv, key);
	if (!hKey)
	{
		CryptReleaseContext(hProv, 0);
		return;
	}

	std::wstring outW;
	for (auto &ln : lines)
	{
		std::wstring trimmed = ln;
		// trim
		while (!trimmed.empty() && iswspace(trimmed.back())) trimmed.pop_back();
		size_t idx = 0; while (idx < trimmed.size() && iswspace(trimmed[idx])) idx++; if (idx) trimmed.erase(0, idx);
		if (trimmed.empty()) { outW.push_back(L'\n'); continue; }

		auto combined = Base64DecodeWide(trimmed);
		if (combined.size() < 16) { // not an encrypted line, keep original
			outW.append(ln);
			outW.push_back(L'\n');
			continue;
		}

		const BYTE* iv = combined.data();
		const BYTE* cipher = combined.data() + 16;
		DWORD cipherLen = (DWORD)(combined.size() - 16);
		if (cipherLen == 0) {
			outW.append(ln);
			outW.push_back(L'\n');
			continue;
		}

		// set IV
		if (!CryptSetKeyParam(hKey, KP_IV, const_cast<BYTE*>(iv), 0))
		{
			// failed to set IV, keep original line
			outW.append(ln);
			outW.push_back(L'\n');
			continue;
		}

		// prepare buffer for CryptDecrypt (in-place)
		std::vector<BYTE> buf(cipherLen);
		memcpy(buf.data(), cipher, cipherLen);
		DWORD dwLen = cipherLen;
		if (!CryptDecrypt(hKey, 0, TRUE, 0, buf.data(), &dwLen))
		{
			// decryption failed for this line, keep original
			outW.append(ln);
			outW.push_back(L'\n');
			continue;
		}

		// dwLen bytes of plaintext in buf
		std::wstring plain = Utf8ToWide(reinterpret_cast<const char*>(buf.data()), dwLen);
		outW.append(plain);
		outW.push_back(L'\n');
	}

	// create new document and set its text (do not modify current document)
	fileNew(); // open new document
	ScintillaEditView* pViewNew = _pEditView;
	if (pViewNew)
	{
		std::string outUtf8 = WideToUtf8(outW);
		pViewNew->execute(SCI_SETTEXT, 0, reinterpret_cast<LPARAM>(outUtf8.c_str()));
	}

	// rename the new untitled tab to original file name + "_解密"
	{
		/*const wchar_t* origName = nullptr;*/
		if (_pEditView && _pEditView->getCurrentBuffer())
		{
			// before fileNew() the current buffer was the original one; but after fileNew() current buffer is new
			// we saved original file name by reading from previous buffer earlier: try to get from pView (we used pView initially)
		}

		fileRenameUntitledPluginAPI(BUFFER_INVALID, newTabName.c_str());
	}

	// cleanup
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
}

void Notepad_plus::decryptConfigFile(const wchar_t* filePath)
{
	std::wstring password = DEFAULT_DECRYPT_PASSWORD;

	// get current file path
	const wchar_t* fullPath = filePath;
	if (!fullPath && _pEditView && _pEditView->getCurrentBuffer())
		fullPath = _pEditView->getCurrentBuffer()->getFullPathName();
	if (!fullPath || fullPath[0] == L'\0')
	{
		MessageBoxW(_pPublicInterface->getHSelf(), L"当前文档未保存到磁盘，无法按文件字节解密。请先保存文件。", L"无法解密", MB_ICONWARNING);
		return;
	}

	std::wstring newTabName = L"decrypted";
	const wchar_t* fn_name = _pEditView->getCurrentBuffer()->getFileName();
	if (fn_name && fn_name[0] != L'\0')
	{
		std::wstring base(fn_name);
		// extract file name and extension using string operations (avoids <filesystem> dependency)
		std::wstring filename = base;
		size_t sep = filename.find_last_of(L"\\/");
		if (sep != std::wstring::npos) filename = filename.substr(sep + 1);
		size_t pos = filename.find_last_of(L'.');
		if (pos == std::wstring::npos || pos == 0)
			newTabName = filename + L"_解密";
		else
			newTabName = filename.substr(0, pos) + L"_解密" + filename.substr(pos);
	}

	// read file bytes from disk
	std::vector<uint8_t> fileBytes;
	HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return;
	DWORD sizeLow = GetFileSize(hFile, NULL);
	if (sizeLow == INVALID_FILE_SIZE) { CloseHandle(hFile); return; }
	if (sizeLow > 0)
	{
		fileBytes.resize(sizeLow);
		DWORD read = 0;
		if (!ReadFile(hFile, fileBytes.data(), sizeLow, &read, NULL) || read != sizeLow)
		{
			CloseHandle(hFile);
			return;
		}
	}
	CloseHandle(hFile);

	if (fileBytes.empty())
		return;

	// derive AES key bytes
	std::vector<uint8_t> key = GetAesKeyFromPassword(password);

	// First try AES-ECB decryption using CNG (BCrypt) which matches C# RijndaelManaged ECB+PKCS7
	auto aesEcbDecrypt = [&key](const uint8_t* data, ULONG dataSize, std::vector<BYTE> & outPlain, NTSTATUS* outStatus) -> bool {
		if (!data || dataSize == 0) return false;
		BCRYPT_ALG_HANDLE hAlg = NULL;
		BCRYPT_KEY_HANDLE hKey = NULL;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!BCRYPT_SUCCESS(status)) return false;

		// set chaining mode to ECB
		status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
		if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); return false; }

		// import or generate key
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
		if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg,0); return false; }

		ULONG cbOutput = 0;
		// first call to get output size (supports padding)
		status = BCryptDecrypt(hKey, (PUCHAR)data, dataSize, NULL, NULL, 0, NULL, 0, &cbOutput, BCRYPT_BLOCK_PADDING);
		if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg,0); return false; }

		outPlain.resize(cbOutput);
		status = BCryptDecrypt(hKey, (PUCHAR)data, dataSize, NULL, NULL, 0, outPlain.data(), cbOutput, &cbOutput, BCRYPT_BLOCK_PADDING);
		if (!BCRYPT_SUCCESS(status)) { if (outStatus) *outStatus = status; BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg,0); outPlain.clear(); return false; }
		// success
		outPlain.resize(cbOutput);
		if (outStatus) *outStatus = 0; // STATUS_SUCCESS
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlg,0);
		return true;
	};
	std::vector<BYTE> plainBytes;
	bool ok = false;

	// If file starts with EncryptedMagic ("ENCRYPTEDv1:"), skip the magic prefix and decrypt remaining bytes
	const char* magic = "ENCRYPTEDv1:";
	size_t magicLen = strlen(magic);
	bool hasMagic = false;
	const uint8_t* ecbData = nullptr;
	ULONG ecbLen = 0;
	if (fileBytes.size() >= magicLen && memcmp(fileBytes.data(), magic, magicLen) == 0)
	{
		hasMagic = true;
		ecbData = fileBytes.data() + magicLen;
		ecbLen = static_cast<ULONG>(fileBytes.size() - magicLen);
	}
	else
	{
		ecbData = fileBytes.data();
		ecbLen = static_cast<ULONG>(fileBytes.size());
	}

	NTSTATUS ecbStatus = 0;
	ok = aesEcbDecrypt(ecbData, ecbLen, plainBytes, &ecbStatus);

	// Diagnostic info collector
	std::wstring diag;
	diag.reserve(1024);
	diag.append(L"EncryptedMagicDetected: ");
	diag.append(hasMagic ? L"Yes\r\n" : L"No\r\n");
	diag.append(L"DerivedKey: ");
	diag.append(BytesToHex(key.data(), key.size()));
	diag.append(L"\r\n");
	// fallback: if ECB didn't work, try CBC using CryptoAPI with IV prefix (existing approach)
	if (!ok)
	{
		// append ECB status
		{
			wchar_t s[128];
			swprintf(s, ARRAYSIZE(s), L"ECB_NTSTATUS: 0x%08X\r\n", (unsigned int)ecbStatus);
			diag.append(s);
		}
		if (fileBytes.size() > 16)
		{
			HCRYPTPROV hProv = 0;
			if (CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			{
				HCRYPTKEY hCapiKey = ImportAesKey(hProv, key);
				if (hCapiKey)
				{
					const BYTE* iv = fileBytes.data();
					const BYTE* cipher = fileBytes.data() + 16;
					DWORD cipherLen = static_cast<DWORD>(fileBytes.size() - 16);
					if (CryptSetKeyParam(hCapiKey, KP_IV, const_cast<BYTE*>(iv), 0))
					{
						std::vector<BYTE> tmp(cipher, cipher + cipherLen);
						DWORD dwLen = cipherLen;
						if (CryptDecrypt(hCapiKey, 0, TRUE, 0, tmp.data(), &dwLen))
						{
							plainBytes.assign(tmp.begin(), tmp.begin() + dwLen);
							ok = true;
							// append partial plaintext for diagnostics
							size_t show = std::min<size_t>(plainBytes.size(), 256);
							diag.append(L"CBC_PlainPrefixHex: ");
							diag.append(BytesToHex(plainBytes.data(), show));
							diag.append(L"\r\n");
						}
					}
					CryptDestroyKey(hCapiKey);
				}
				CryptReleaseContext(hProv, 0);
			}
		}
	}

	if (!ok)
	{
		// append last Win32 error for CryptoAPI path
		DWORD lastErr = GetLastError();
		wchar_t tmpErr[128];
		swprintf(tmpErr, ARRAYSIZE(tmpErr), L"CryptoAPI_GetLastError: 0x%08X\r\n", (unsigned int)lastErr);
		diag.append(tmpErr);

		// show diagnostics to user to help debugging
		// limit diag to reasonable length
		if (diag.size() > 4000) diag.resize(4000);
		MessageBoxW(_pPublicInterface->getHSelf(), diag.c_str(), L"解密诊断信息", MB_ICONWARNING);

		MessageBoxW(_pPublicInterface->getHSelf(), L"无法解密该配置文件（尝试 AES-ECB/CBC）。", L"解密失败", MB_ICONERROR);
		return;
	}

	// convert decrypted bytes (assume UTF-8) to wide and open in new document
	std::wstring plain = Utf8ToWide(reinterpret_cast<const char*>(plainBytes.data()), plainBytes.size());

	// create new document and set its text
	//fileNew(); // open new document
	ScintillaEditView* pView = _pEditView;
	if (pView)
	{
		std::string outUtf8 = WideToUtf8(plain);
		pView->execute(SCI_SETTEXT, 0, reinterpret_cast<LPARAM>(outUtf8.c_str()));
		// simulate user selecting menu: Encoding -> UTF-8
		if (_pPublicInterface)
		{
			::SendMessageW(_pPublicInterface->getHSelf(), WM_COMMAND, MAKEWPARAM(IDM_FORMAT_UTF_8, 0), 0);
		}
	}
	// rename the new untitled tab to original file name + "_解密"
	//{
	//	/*const wchar_t* origName = nullptr;*/
	//	if (_pEditView && _pEditView->getCurrentBuffer())
	//	{
	//		 before fileNew() the current buffer was the original one; but after fileNew() current buffer is new
	//		 we saved original file name by reading from previous buffer earlier: try to get from pView (we used pView initially)
	//	}
	//	
	//	fileRenameUntitledPluginAPI(BUFFER_INVALID, newTabName.c_str());
	//}
}
