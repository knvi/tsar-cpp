#include <string>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>
#include <base.hpp>
#include <iostream>

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
}

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
} Subscription;

typedef struct Data
{
    User user;
    Subscription subscription;
    long long timestamp;
    std::string hwid;
} Data;

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

std::string data_bytes_to_string(const std::string &data_bytes)
{
    return std::string(data_bytes.begin(), data_bytes.end());
}

Data string_to_data(const std::string &json_string)
{
    nlohmann::json json = nlohmann::json::parse(json_string);

    Data data;

    data.user.id = json["user"]["id"];
    data.user.username = json["user"]["username"];
    data.user.avatar = json["user"]["avatar"];

    data.subscription.id = json["subscription"]["id"];
    data.subscription.expires = json["subscription"]["expires"];

    data.timestamp = json["timestamp"];
    data.hwid = json["hwid"];

    return data;
}

class Client
{
public:
    std::string app_id;
    std::string client_key;

    Client(std::string &app_id, std::string &client_key) : app_id(app_id), client_key(client_key) {}

    Data authenticate_user()
    {
        std::string hwid = get_hwid();
        std::cout << "hwid = " << hwid << "\n";
        return validate_user(hwid);
    }

    static size_t write_callback(void *cnts, size_t size, size_t nmemb, void *userp)
    {
        ((std::string *)userp)->append((char *)cnts, size * nmemb);
        return size * nmemb;
    }

    Data validate_user(std::string &hwid)
    {
        std::string pub_key_bytes = base64_decode(client_key);

        EVP_PKEY *pub_key = EVP_PKEY_new();

        std::stringstream ss;
        ss << "https://tsar.cc/api/client/v1/subscriptions/validate?app=" << this->app_id
           << "&hwid=" << hwid;
        std::string url = ss.str();

        CURL *curl = curl_easy_init();
        CURLcode res;
        std::string response;

        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode code = curl_easy_perform(curl);
            std::cout << "url " << url << ", code " << int(code) << "\n";
            if (code != CURLE_OK)
                std::cout << "not ok;";

            std::cout << "response = " << response << "\n";

            nlohmann::json data = nlohmann::json::parse(response);

            std::string base64_data = data["data"];
            std::string signature = data["signature"];

            std::string decoded_data = base64_decode(base64_data);
            std::string decoded_signature = base64_decode(signature);

            std::string json_string = data_bytes_to_string(decoded_data);

            std::cout << "json_string = " << json_string << "\n";

            Data json = string_to_data(json_string);

            bool result = verify_signature(pub_key, json_string, decoded_signature);

            if (!result)
            {
                return Data();
            }
        }
    }
};

int main()
{
    std::string appId = "58816206-b24c-41d4-a594-8500746a78ee";
    std::string publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5CnFUF4qSGfrLN84Dlo8zMgRjnCLRlCP+ddg6XgDFfvIhC+4w+frn0doqohQo0Y71TXK2fqbrD0FgFtc6N+XXQ==";

    Client client(appId, publicKey);

    Data data = client.authenticate_user();
    std::cout << "data[\"user\"][\"name\"] = " << data.user.username << "\n";
    return 0;
}