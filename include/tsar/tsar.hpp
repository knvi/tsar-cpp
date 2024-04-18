#ifndef TSAR_HPP
#define TSAR_HPP

#include <string>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>
#include <base.hpp>
#include <iostream>
#include <obfy.hpp>

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#include <windows.h>

#elif defined(__linux__) || defined(__unix__)
#include <fstream>

#elif defined(__APPLE__) && defined(__MACH__)
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <array>

#endif
/// ---!!! UTILS !!!---

/// @brief Get the hardware ID of the system
/// @return std::string
std::string get_hwid()
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    HKEY hKey;
    DWORD bufLen = 1024;
    char szBuffer[1024];
    DWORD dwDataType;

    std::string subKey = "SOFTWARE\\Microsoft\\Cryptography";
    std::string valueName = "MachineGuid";

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueEx(hKey, valueName.c_str(), 0, &dwDataType, (LPBYTE)szBuffer, &bufLen) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return std::string(szBuffer);
        }
        RegCloseKey(hKey);
    }

#elif defined(__linux__) || defined(__unix__)
    std::vector<std::string> paths = {"/var/lib/dbus/machine-id", "/etc/machine-id"};
    for (std::string &path : paths)
    {
        FILE *fptr;

        // Open a file in read mode
        fptr = fopen(path.c_str(), "r");
        if (fptr)
        {
            char mySID[100];

            fgets(mySID, 100, fptr);
            std::string SIDString = std::string(mySID);
            SIDString.erase(remove_if(SIDString.begin(), SIDString.end(), isspace), SIDString.end());
            fclose(fptr);
            return SIDString;
        }
        fclose(fptr);
    }
    std::cout << "cannot find SID for your Linux system\n";

#elif defined(__APPLE__) && defined(__MACH__)
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen("ioreg -rd1 -c IOExpertPlatformDevice", "r"), pclose);
    if (!pipe)
        throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get()))
    {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;

#endif
    return "";
}

/// @brief Verify the signature of the data
/// @param pub_key Public key
/// @param data Data to verify
/// @param signature Signature to verify
/// @return bool - True if the signature is valid, false otherwise
bool verify_signature(EVP_PKEY *pub_key, const std::string &data, const std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    int res = 0;

    if (!(mdctx = EVP_MD_CTX_create()))
    {
        return false;
    }

    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key))
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.size()))
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    res = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature.c_str(), signature.size());

    EVP_MD_CTX_free(mdctx);

    return res == 1;
}

/// @brief Convert data bytes to string
/// @param data_bytes Data bytes
/// @return std::string
std::string data_bytes_to_string(const std::string &data_bytes)
{
    return std::string(data_bytes.begin(), data_bytes.end());
}

/// @brief Open a URL in the default browser
/// @param url URL to open
void open_url(const std::string &url)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    system(("start " + url).c_str());

#elif defined(__linux__) || defined(__unix__)
    system(("xdg-open " + url).c_str());

#elif defined(__APPLE__) && defined(__MACH__)
    system(("open " + url).c_str());

#endif
}

/// @brief Perform a `GET` request
/// @param url URL to get
/// @param response Response
/// @param write_callback Callback function
/// @param response_code Response code
/// @return int - 1 if the request was successful, 0 otherwise
int get_request(const std::string &url, std::string &response, size_t write_callback(void *cnts, size_t size, size_t nmemb, void *userp), int &response_code)
{
    CURL *curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_cleanup(curl);

        return 1;
    }

    return 0;
}

/// @brief Validate the result
/// @param response Response
/// @param signature Signature
/// @param pub_key Public key
/// @return int - 1 if the result is valid, 0 otherwise
int validate_result(const std::string &response, const std::string &signature, EVP_PKEY *pub_key)
{
    std::string decoded_data = base64_decode(response);
    std::string decoded_signature = base64_decode(signature);

    std::string json_string = data_bytes_to_string(decoded_data);

    bool result = verify_signature(pub_key, json_string, decoded_signature);

    if (result == true)
    {
        return 1;
    }

    return 0;
}

/// ---!!! STRUCTS !!!---

typedef struct User
{
    std::string id;
    std::string username;
    std::string avatar;
} User;

typedef struct Subscription
{
    std::string id;
    long long expires;
    User user;
} Subscription;

typedef struct Data
{
    Subscription subscription;
    long long timestamp;
    std::string hwid;
    std::string session;
} Data;

Data string_to_data(const std::string &json_string)
{
    nlohmann::json json = nlohmann::json::parse(json_string);

    Data data;

    data.subscription.id = json["subscription"]["id"];
    if (json["subscription"]["expires"].is_number())
    {
        data.subscription.expires = json["subscription"]["expires"];
    }

    data.subscription.user.id = json["subscription"]["user"]["id"];
    if (json["subscription"]["user"]["username"].is_string())
    {
        data.subscription.user.username = json["subscription"]["user"]["username"];
    }
    if (json["subscription"]["user"]["avatar"].is_string())
    {
        data.subscription.user.avatar = json["subscription"]["user"]["avatar"];
    }

    data.timestamp = json["timestamp"];
    data.hwid = json["hwid"];
    data.session = json["session"];

    return data;
}

/// ---!!! CLIENT !!!---

class Client
{
public:
    std::string app_id;
    std::string client_key;
    std::string hwid;
    std::string session;
    Subscription subscription;

    Client(std::string &app_id, std::string &client_key) : app_id(app_id), client_key(client_key) {
        this->hwid = get_hwid();

        if (this->hwid.empty())
        {
            std::cout << "Failed to get HWID\n";
            exit(1);
        }

        Data data = this->validate_user();

        this->subscription = data.subscription;
        this->session = data.session;

    }

    static size_t write_callback(void *cnts, size_t size, size_t nmemb, void *userp)
    {
        ((std::string *)userp)->append((char *)cnts, size * nmemb);
        return size * nmemb;
    }

    Data validate_user()
    {
        std::string pub_key_bytes = base64_decode(client_key);

        EVP_PKEY *pub_key = EVP_PKEY_new();

        std::stringstream ss;
        ss << "https://tsar.cc/api/client/subscriptions/get?app=" << this->app_id
           << "&hwid=" << this->hwid;
        std::string url = ss.str();

        std::cout << "URL: " << url << "\n";

        std::string response;
        int response_code;

        if (get_request(url, response, write_callback, response_code) == 1) {
            if (response_code == 401) {
                std::cout << "Subscription not found. Please re-run this command once you authenticate.\n";
                std::string url = "https://tsar.cc/auth/" + this->app_id + "/" + hwid;
                
                open_url(url);

                exit(1);
            }

            nlohmann::json data = nlohmann::json::parse(response);

            std::string signature = data["signature"];
            std::string data_bytes = data["data"];

            std::string decoded_data = base64_decode(data_bytes);
            std::string decoded_signature = base64_decode(signature);

            std::string json_string = data_bytes_to_string(decoded_data);

            if (validate_result(json_string, decoded_signature, pub_key) == 0)
            {
                std::cout << "Failed to validate result\n";
                return Data();
            }

            return string_to_data(json_string);

        } else {
            std::cout << "Failed to get request\n";
            return Data();
        }
    }
};

#endif