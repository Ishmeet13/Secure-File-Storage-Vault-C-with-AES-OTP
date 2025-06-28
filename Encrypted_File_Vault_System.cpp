// ==========================================
// Encrypted File Vault System (C++) 
// ==========================================
// Features:
// - AES-256 encryption/decryption (OpenSSL)
// - SHA-256 password hashing
// - Role-based access (Admin, Editor, Viewer)
// - OTP-secured downloads
// - File versioning with rollback, metadata, cleanup
// - Visual diff for text files
// - CSV-based audit logs
// - Recursive folder upload/download
// - Admin Panel (view/reset/delete users, revoke files)
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <regex>
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <ctime>
#include <random>
#include <mutex>
#include <map>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

namespace fs = std::filesystem;
std::mutex log_mutex;
const std::string LOG_FILE = "audit_log.csv";
const std::string VAULT_DIR = "vault/";
const std::string DOWNLOAD_DIR = "downloads/";
const std::string USERS_DB = "users.db";
const std::string SHARED_LINKS_DB = "shared_links.db";
const int MAX_VERSIONS = 5;

struct User {
    std::string username;
    std::string password_hash;
    std::string role;
};

std::unordered_map<std::string, User> users;
std::map<std::string, std::pair<std::string, std::string>> security_questions;

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string generate_token() {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string token;
    for (int i = 0; i < 16; ++i)
        token += alphanum[rand() % (sizeof(alphanum) - 1)];
    return token;
}

void generate_share_link(const std::string& user) {
    std::string filename, pass;
    int expiry;
    std::cout << "Enter base filename to share: "; std::cin >> filename;
    std::cout << "Set password (optional): "; std::cin.ignore(); std::getline(std::cin, pass);
    std::cout << "Expiry time (minutes): "; std::cin >> expiry;

    std::string token = generate_token();
    std::ofstream out(SHARED_LINKS_DB, std::ios::app);
    out << token << " " << filename << " " << (pass.empty() ? "-" : sha256(pass)) << " " << (std::time(nullptr) + expiry * 60) << " 0\n";
    std::cout << "Generated share link token: " << token << "\n";
    log_action(user, "generate_link", filename, token);
}

void use_shared_link() {
    std::string token, input_pass;
    std::cout << "Enter token: "; std::cin >> token;

    std::ifstream fin(SHARED_LINKS_DB);
    std::vector<std::string> lines;
    std::string t, file, hash, exp, used;
    bool found = false;

    while (fin >> t >> file >> hash >> exp >> used) {
        if (t == token && used == "0" && std::time(nullptr) < std::stol(exp)) {
            if (hash != "-") {
                std::cout << "Enter password: "; std::cin >> input_pass;
                if (sha256(input_pass) != hash) {
                    std::cout << "Incorrect password.\n"; return;
                }
            }
            std::string in = VAULT_DIR + file;
            std::string out = DOWNLOAD_DIR + file + ".dec";
            if (decrypt_file(in, out)) std::cout << "Downloaded to: " << out << "\n";
            else std::cout << "Decryption failed.\n";
            found = true;
        }
        lines.push_back(t + " " + file + " " + hash + " " + exp + " " + (t == token ? "1" : used));
    }
    fin.close();
    std::ofstream fout(SHARED_LINKS_DB);
    for (const auto& line : lines) fout << line << "\n";
    if (!found) std::cout << "Invalid or expired token.\n";
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string timestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void log_action(const std::string& user, const std::string& action, const std::string& file, const std::string& status) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::ofstream out(LOG_FILE, std::ios::app);
    out << user << "," << action << "," << timestamp() << "," << file << "," << status << "\n";
}

bool encrypt_file(const std::string& in, const std::string& out) {
    std::ifstream ifs(in, std::ios::binary);
    std::ofstream ofs(out, std::ios::binary);
    if (!ifs || !ofs) return false;

    unsigned char key[32], iv[16];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    ofs.write((char*)key, 32);
    ofs.write((char*)iv, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    while ((inlen = ifs.read(inbuf, sizeof(inbuf)).gcount()) > 0) {
        EVP_EncryptUpdate(ctx, (unsigned char*)outbuf, &outlen, (unsigned char*)inbuf, inlen);
        ofs.write(outbuf, outlen);
    }
    EVP_EncryptFinal_ex(ctx, (unsigned char*)outbuf, &outlen);
    ofs.write(outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool decrypt_file(const std::string& in, const std::string& out) {
    std::ifstream ifs(in, std::ios::binary);
    std::ofstream ofs(out, std::ios::binary);
    if (!ifs || !ofs) return false;

    unsigned char key[32], iv[16];
    ifs.read((char*)key, 32);
    ifs.read((char*)iv, 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    while ((inlen = ifs.read(inbuf, sizeof(inbuf)).gcount()) > 0) {
        EVP_DecryptUpdate(ctx, (unsigned char*)outbuf, &outlen, (unsigned char*)inbuf, inlen);
        ofs.write(outbuf, outlen);
    }
    EVP_DecryptFinal_ex(ctx, (unsigned char*)outbuf, &outlen);
    ofs.write(outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

int get_next_version(const std::string& base) {
    int max_ver = 0;
    for (const auto& entry : fs::directory_iterator(VAULT_DIR)) {
        std::string name = entry.path().filename().string();
        if (name.find(base + "_v") == 0) {
            int v = std::stoi(name.substr(name.find("_v") + 2));
            max_ver = std::max(max_ver, v);
        }
    }
    return max_ver + 1;
}

void cleanup_versions(const std::string& base) {
    std::vector<std::pair<int, fs::path>> versions;
    for (const auto& entry : fs::directory_iterator(VAULT_DIR)) {
        std::string name = entry.path().filename().string();
        if (name.find(base + "_v") == 0) {
            int v = std::stoi(name.substr(name.find("_v") + 2));
            versions.emplace_back(v, entry.path());
        }
    }
    std::sort(versions.begin(), versions.end());
    while (versions.size() > MAX_VERSIONS) {
        fs::remove(versions.front().second);
        versions.erase(versions.begin());
    }
}

std::string generate_otp() {
    std::random_device rd;
    std::uniform_int_distribution<> dist(100000, 999999);
    return std::to_string(dist(rd));
}

bool verify_otp() {
    std::string otp = generate_otp();
    std::cout << "OTP: " << otp << "\nEnter OTP: ";
    std::string input;
    std::cin >> input;
    return input == otp;
}

void upload_file(const std::string& user) {
    std::string path;
    std::cout << "Enter file/folder to upload: ";
    std::cin >> path;
    if (fs::is_directory(path)) {
        for (auto& p : fs::recursive_directory_iterator(path)) {
            if (fs::is_regular_file(p)) {
                std::string base = p.path().filename().string();
                int v = get_next_version(base);
                std::string target = VAULT_DIR + base + "_v" + std::to_string(v);
                encrypt_file(p.path().string(), target);
                cleanup_versions(base);
                log_action(user, "upload", base, "success");
            }
        }
    } else if (fs::is_regular_file(path)) {
        std::string base = fs::path(path).filename().string();
        int v = get_next_version(base);
        std::string target = VAULT_DIR + base + "_v" + std::to_string(v);
        encrypt_file(path, target);
        cleanup_versions(base);
        log_action(user, "upload", base, "success");
    } else {
        std::cout << "Invalid path.\n";
    }
}

void download_file(const std::string& user) {
    std::string base;
    std::cout << "Enter base filename: ";
    std::cin >> base;
    std::cout << "Available versions:\n";
    for (const auto& entry : fs::directory_iterator(VAULT_DIR)) {
        std::string name = entry.path().filename().string();
        if (name.find(base + "_v") == 0) {
            auto size = fs::file_size(entry.path());
            auto time = fs::last_write_time(entry.path());
            std::time_t t = decltype(time)::clock::to_time_t(time);
            std::cout << name << "\tSize: " << size << "\tTime: " << std::ctime(&t);
        }
    }
    std::string ver;
    std::cout << "Enter version to download: ";
    std::cin >> ver;
    if (!verify_otp()) return;
    std::string in = VAULT_DIR + ver;
    std::string out = DOWNLOAD_DIR + ver + ".dec";
    if (decrypt_file(in, out)) {
        log_action(user, "download", ver, "success");
    } else {
        log_action(user, "download", ver, "fail");
    }
}

void rollback_version(const std::string& user) {
    std::string base;
    std::cout << "Enter base filename: ";
    std::cin >> base;
    int target;
    std::cout << "Enter version to rollback to: ";
    std::cin >> target;
    std::string from = VAULT_DIR + base + "_v" + std::to_string(target);
    int next = get_next_version(base);
    std::string to = VAULT_DIR + base + "_v" + std::to_string(next);
    fs::copy(from, to);
    cleanup_versions(base);
    log_action(user, "rollback", base, "v" + std::to_string(target));
}

void show_diff(const std::string& file1, const std::string& file2) {
    std::ifstream f1(file1), f2(file2);
    std::string l1, l2;
    int line = 1;
    while (std::getline(f1, l1) && std::getline(f2, l2)) {
        if (l1 != l2)
            std::cout << "Line " << line << ":\n- " << l1 << "\n+ " << l2 << "\n";
        ++line;
    }
}

void admin_panel() {
    int choice;
    do {
        std::cout << "\nAdmin Panel:\n1. View Users\n2. Reset Password\n3. Delete User\n4. Revoke File\n0. Back\nChoice: ";
        std::cin >> choice;
        if (choice == 1) {
            std::ifstream fin(USERS_DB);
            std::string u, p, r;
            while (fin >> u >> p >> r) std::cout << u << " (" << r << ")\n";
        } else if (choice == 2) {
            std::string u, np;
            std::cout << "User: "; std::cin >> u;
            std::cout << "New Password: "; std::cin >> np;
            std::ifstream fin(USERS_DB);
            std::vector<std::string> lines;
            std::string usr, pass, role;
            while (fin >> usr >> pass >> role) {
                if (usr == u) pass = sha256(np);
                lines.push_back(usr + " " + pass + " " + role);
            }
            fin.close();
            std::ofstream fout(USERS_DB);
            for (auto& l : lines) fout << l << "\n";
        } else if (choice == 3) {
            std::string u;
            std::cout << "User to delete: "; std::cin >> u;
            std::ifstream fin(USERS_DB);
            std::vector<std::string> lines;
            std::string usr, pass, role;
            while (fin >> usr >> pass >> role) {
                if (usr != u) lines.push_back(usr + " " + pass + " " + role);
            }
            fin.close();
            std::ofstream fout(USERS_DB);
            for (auto& l : lines) fout << l << "\n";
        } else if (choice == 4) {
            std::string f;
            std::cout << "File to revoke: "; std::cin >> f;
            fs::remove(VAULT_DIR + f);
        }
    } while (choice != 0);
}
// [Additional Password Recovery Features]

std::map<std::string, std::pair<std::string, std::string>> security_questions; // username -> {question, answer}

void load_security_questions() {
    std::ifstream fin("security_qna.db");
    std::string user, question, answer;
    while (std::getline(fin, user) && std::getline(fin, question) && std::getline(fin, answer)) {
        security_questions[user] = {question, answer};
    }
}

void save_security_questions() {
    std::ofstream fout("security_qna.db");
    for (const auto& [user, qa] : security_questions) {
        fout << user << "\n" << qa.first << "\n" << qa.second << "\n";
    }
}

void register_user() {
    std::string username, password, role, question, answer;
    std::cout << "Choose username: "; std::cin >> username;
    std::cout << "Choose password: "; std::cin >> password;
    std::cout << "Role (Admin/Editor/Viewer): "; std::cin >> role;
    std::cout << "Security question: "; std::cin.ignore(); std::getline(std::cin, question);
    std::cout << "Answer: "; std::getline(std::cin, answer);
    std::ofstream fout(USERS_DB, std::ios::app);
    fout << username << " " << sha256(password) << " " << role << "\n";
    fout.close();
    security_questions[username] = {question, answer};
    save_security_questions();
    std::cout << "User registered successfully.\n";
}

void recover_password() {
    std::string username;
    std::cout << "Enter username for recovery: "; std::cin >> username;
    if (security_questions.find(username) == security_questions.end()) {
        std::cout << "No recovery data found.\n"; return;
    }
    std::cout << "Answer this to reset password:\n" << security_questions[username].first << "\n> ";
    std::string input;
    std::cin.ignore(); std::getline(std::cin, input);
    if (input == security_questions[username].second) {
        std::string newpass;
        std::cout << "Correct. Enter new password: "; std::cin >> newpass;
        std::ifstream fin(USERS_DB);
        std::vector<std::string> lines;
        std::string u, p, r;
        while (fin >> u >> p >> r) {
            if (u == username) p = sha256(newpass);
            lines.push_back(u + " " + p + " " + r);
        }
        fin.close();
        std::ofstream fout(USERS_DB);
        for (auto& line : lines) fout << line << "\n";
        std::cout << "Password reset successful.\n";
    } else {
        std::cout << "Incorrect answer.\n";
    }
}
void send_email_otp(const std::string& email, const std::string& otp) {
    std::string command = "echo OTP for download is: " + otp + " | mail -s 'Your Secure Vault OTP' " + email;
    system(command.c_str());
}

bool verify_email_otp(const std::string& email) {
    std::string otp = generate_otp();
    send_email_otp(email, otp);
    std::string input;
    std::cout << "OTP sent to your email. Enter OTP: ";
    std::cin >> input;
    return input == otp;
}
namespace fs = std::filesystem;
std::mutex log_mutex;
const std::string LOG_FILE = "audit_log.csv";
const std::string VAULT_DIR = "vault/";
const std::string DOWNLOAD_DIR = "downloads/";
const std::string USERS_DB = "users.db";
const std::string SHARED_LINKS_DB = "shared_links.db";
const int MAX_VERSIONS = 5;

struct User {
    std::string username;
    std::string password_hash;
    std::string role;
};

std::unordered_map<std::string, User> users;

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

int main() {
    fs::create_directory(VAULT_DIR);
    fs::create_directory(DOWNLOAD_DIR);
    load_security_questions();

    int first_choice;
    std::cout << "Welcome to the Encrypted File Vault System\n";
    std::cout << "Select an option:\n";
    std::cout << "-1. Register\n-2. Recover Password\n-3. Email-OTP Protected Download\n 0. Login\nChoice: ";
    std::cin >> first_choice;

    if (first_choice == -1) {
        register_user(); return 0;
    } else if (first_choice == -2) {
        recover_password(); return 0;
    } else if (first_choice == -3) {
        std::string email;
        std::cout << "Enter your email: "; std::cin >> email;
        if (!verify_email_otp(email)) {
            std::cout << "OTP verification failed.\n"; return 0;
        }
        std::string file;
        std::cout << "Enter filename to download: "; std::cin >> file;
        std::string in = VAULT_DIR + file;
        std::string out = DOWNLOAD_DIR + file + ".dec";
        if (decrypt_file(in, out)) std::cout << "Decrypted to " << out << "\n";
        else std::cout << "Decryption failed.\n";
        return 0;
    }

    std::string username, password;
    std::cout << "Username: "; std::cin >> username;
    std::cout << "Password: "; std::cin >> password;

    std::ifstream fin(USERS_DB);
    std::string u, p, r;
    bool authenticated = false;
    while (fin >> u >> p >> r) {
        if (u == username && p == sha256(password)) {
            users[username] = { u, p, r }; authenticated = true; break;
        }
    }
    if (!authenticated) {
        std::cout << "\nLogin failed.\n"; return 0;
    }

    std::string role = users[username].role;
    std::cout << "\nWelcome, " << username << " (Role: " << role << ")\n";
    int choice;
    do {
        std::cout << "\n1. Upload\n2. Download\n3. Rollback\n4. Diff\n";
        if (role == "Admin") std::cout << "5. Admin Panel\n";
        std::cout << "6. Generate Share Link\n7. Use Share Link\n0. Exit\nChoice: ";
        std::cin >> choice;

        if (choice == 1) upload_file(username);
        else if (choice == 2) download_file(username);
        else if (choice == 3) rollback_version(username);
        else if (choice == 4) {
            std::string f1, f2;
            std::cout << "First file: "; std::cin >> f1;
            std::cout << "Second file: "; std::cin >> f2;
            show_diff(f1, f2);
        }
        else if (choice == 5 && role == "Admin") admin_panel();
        else if (choice == 6) generate_share_link(username);
        else if (choice == 7) use_shared_link();
    } while (choice != 0);

    return 0;
}

}

}

