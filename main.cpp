#include <iostream>
#include <crow.h>
#include <string>
#include <sqlite3.h>
#include <filesystem>
#include <ctime>
#include <fstream>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/evp.h>

sqlite3 *db = nullptr;
std::filesystem::path g_base_dir;

bool is_valid_ipv4(const std::string &ip) {
    int parts = 0, val = 0, dots = 0;
    bool in_num = false;
    for (char c : ip) {
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return false;
            in_num = true;
        } else if (c == '.') {
            if (!in_num) return false;
            dots++; parts++; val = 0; in_num = false;
        } else return false;
    }
    if (in_num) parts++;
    return parts == 4 && dots == 3;
}

bool is_valid_wg_key(const std::string &key) {
    if (key.size() != 44) return false;
    for (char c : key)
        if (!isalnum(c) && c != '+' && c != '/' && c != '=') return false;
    return true;
}

std::string read_template(const std::string &name) {
    std::ifstream file(g_base_dir / "templates" / name);
    if (!file.is_open()) {
        std::cerr << "Cannot open template: " << name << std::endl;
        return "<h1>Template not found: " + name + "</h1>";
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

bool execSql(sqlite3 *db, const std::string &sql) {
    char *errorMessage = nullptr;
    int rc = sqlite3_exec(
        db,
        sql.c_str(),
        nullptr,
        nullptr,
        &errorMessage
    );
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: "
                << (errorMessage ? errorMessage : "unknown error")
                << std::endl;
        sqlite3_free(errorMessage);
        return false;
    }
    return true;
}

bool create_tables(sqlite3 *db) {
    if (!execSql(db, R"(
        CREATE TABLE IF NOT EXISTS user (
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            ip TEXT NOT NULL,
            token TEXT,
            login_time INTEGER,
            session_time INTEGER DEFAULT 3600
        );
    )")) {
        return false;
    }
    if (!execSql(db, R"(
        CREATE TABLE IF NOT EXISTS wireguard_clients (
            name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            ip TEXT NOT NULL
        );
    )"))
        return false;
    return true;
}

int db_recreation(sqlite3 *&db, auto c) {
    sqlite3_close(db);
    if (!std::filesystem::remove("database")) {
        std::cerr << "Failed delete the junk file" << std::endl;
        return 1;
    }
    c = sqlite3_open("database", &db);
    if (c != SQLITE_OK) {
        std::cerr << "Failed create the database" << std::endl;
        return 2;
    }
    return 0;
}

struct AuthMiddleware {
    struct context {
    };

    void before_handle(crow::request &req, crow::response &res, context &ctx) {
        if (req.url == "/login" || req.url == "/api/setup") return;
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db, "SELECT ip, login_time, session_time, token FROM user LIMIT 1;", -1, &stmt, nullptr);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            res.redirect("/login");
            res.end();
            return;
        }
        auto raw_ip    = sqlite3_column_text(stmt, 0);
        int  login_time   = sqlite3_column_int(stmt, 1);
        int  session_time = sqlite3_column_int(stmt, 2);
        auto raw_token = sqlite3_column_text(stmt, 3);
        std::string ip       = raw_ip    ? reinterpret_cast<const char*>(raw_ip)    : "";
        std::string db_token = raw_token ? reinterpret_cast<const char*>(raw_token) : "";
        sqlite3_finalize(stmt);
        if (ip != req.remote_ip_address) {
            res.redirect("/login");
            res.end();
            return;
        }
        int now = (int)std::time(nullptr);
        if (now - login_time > session_time) {
            res.redirect("/login");
            res.end();
            return;
        }
        std::string token;
        std::string cookie = req.get_header_value("Cookie");
        auto pos = cookie.find("token=");
        if (pos != std::string::npos) {
            token = cookie.substr(pos + 6);
            auto end = token.find(';');
            if (end != std::string::npos) token = token.substr(0, end);
        }
        if (db_token != token) {
            res.redirect("/login");
            res.end();
            return;
        }
    }

    void after_handle(crow::request &req, crow::response &res, context &ctx) {
        std::cout << req.url << "->" << res.code << std::endl;
    }
};

std::string hash_password(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(password.c_str()), password.size(), hash);
    std::stringstream ss;
    for (unsigned char i: hash)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) i;
    return ss.str();
}

std::string random_session_token() {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string token;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int) chars.size() - 1);
    for (int i = 0; i < 64; i++) {
        token += chars[dis(gen)];
    }
    return token;
}

std::string exec(const std::string &cmd) {
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buffer[256];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

std::string wireguard_active() {
    if (exec("systemctl is-active wg-quick@wg0").find("active") != std::string::npos) return "true";
    return "false";
}

std::string wireguard_clients() {
    std::string out = exec("wg show wg0 peers | wc -l");
    out.erase(0, out.find_first_not_of(" \t\n\r"));
    out.erase(out.find_last_not_of(" \t\n\r") + 1);
    return out;
}

std::string format_bytes(long long bytes) {
    std::stringstream ss;
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
    if (bytes < 1024 * 1024 * 1024) return std::to_string(bytes / 1024 / 1024) + " MB";
    if (bytes < 1024LL * 1024LL * 1024LL * 1024LL) return std::to_string(bytes / 1024 / 1024 / 1024) + " GB";
    return std::to_string(bytes / 1024LL / 1024LL / 1024LL / 1024LL) + " TB";
}

std::string wireguard_bandwidth() {
    std::string out = exec("wg show wg0 transfer");
    long long total = 0;
    std::istringstream ss(out);
    std::string peer, rx, tx;
    while (ss >> peer >> rx >> tx) {
        total += stoll(rx);
        total += stoll(tx);
    }
    return format_bytes(total);
}

std::string to_base64(const std::string &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    char *ptr;
    long len = BIO_get_mem_data(mem, &ptr);
    std::string result(ptr, len);
    BIO_free_all(b64);
    return result;
}

int main(int argc, char *argv[]) {
    g_base_dir = std::filesystem::canonical(argv[0]).parent_path();

    int c = sqlite3_open("database", &db);
    if (c != SQLITE_OK) {
        int o = db_recreation(db, c);
        if (o == 1) {
            std::cerr << "Failed delete the junk file" << std::endl;
            return 1;
        }
        if (o == 2) {
            std::cerr << "Failed create the database file" << std::endl;
            return 1;
        }
    }
    std::string sql = "PRAGMA schema_version;";
    char *errorMessage = nullptr;
    int rc = sqlite3_exec(
        db,
        sql.c_str(),
        nullptr,
        nullptr,
        &errorMessage
    );
    if (rc != SQLITE_OK) {
        int o = db_recreation(db, c);
        if (o == 1) {
            std::cerr << "Failed delete the junk file" << std::endl;
            return 1;
        }
        if (o == 2) {
            std::cerr << "Failed create the database file" << std::endl;
            return 1;
        }
    }
    sqlite3_free(errorMessage);
    if (!create_tables(db)) {
        std::cerr << "Failed create database" << std::endl;
        return 1;
    }
    crow::App<AuthMiddleware> app;
    CROW_ROUTE(app, "/login").methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST)([](const crow::request &req) {
        if (req.method == crow::HTTPMethod::GET) {
            crow::response res;
            res.set_header("Content-Type", "text/html");
            res.body = read_template("login.html");
            return res;
        }
        crow::response res;
        auto params = req.get_body_params();
        sqlite3_stmt *stmt;
        std::string username = params.get("username");
        std::string password = params.get("password");
        sqlite3_prepare_v2(db, "SELECT username FROM user;", -1, &stmt, nullptr);
        sqlite3_step(stmt);
        std::string db_username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "SELECT password_hash FROM user;", -1, &stmt, nullptr);
        sqlite3_step(stmt);
        std::string db_password_hash = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        if (hash_password(password) != db_password_hash || db_username != username) {
            res.redirect("/login?error=1");
            return res;
        }
        std::string token = random_session_token();
        sqlite3_prepare_v2(db, "UPDATE user SET token = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        res.set_header("Set-Cookie", "token=" + token + "; HttpOnly");
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "UPDATE user SET ip = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, req.remote_ip_address.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "UPDATE user SET login_time = ?;", -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, (int) std::time(nullptr));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        res.redirect("/");
        return res;
    });
    CROW_ROUTE(app, "/")([](const crow::request &req) {
        crow::response res;
        res.set_header("Content-Type", "text/html");
        res.body = read_template("main_page.html");
        return res;
    });
    CROW_ROUTE(app, "/api/status").methods(crow::HTTPMethod::GET)([](const crow::request &req) {
        crow::json::wvalue data;
        data["wireguard"] = wireguard_active();
        data["wireguard_clients"] = wireguard_clients();
        data["wireguard_bandwidth"] = wireguard_bandwidth();
        return crow::response{data};
    });
    CROW_ROUTE(app, "/api/wireguard_status").methods(crow::HTTPMethod::GET)([](const crow::request &req) {
        crow::json::wvalue data;
        crow::json::wvalue::list peers;
        data["wireguard"] = wireguard_active();
        data["wireguard_clients"] = wireguard_clients();
        data["wireguard_bandwidth"] = wireguard_bandwidth();
        std::string out = exec("wg show wg0 dump");
        std::istringstream ss(out);
        std::string line;
        bool first_line = true;
        while (std::getline(ss, line)) {
            if (first_line) { first_line = false; continue; }
            if (line.empty()) continue;
            std::istringstream ls(line);
            std::string key, preshared, endpoint, allowed, handshake, rx, tx;
            ls >> key >> preshared >> endpoint >> allowed >> handshake >> rx >> tx;
            if (key.empty()) continue;
            crow::json::wvalue peer;
            sqlite3_stmt *stmt;
            sqlite3_prepare_v2(db, "SELECT name FROM wireguard_clients WHERE public_key = ?;", -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            auto raw = sqlite3_column_text(stmt, 0);
            std::string name = raw ? reinterpret_cast<const char *>(raw) : key;
            sqlite3_finalize(stmt);
            peer["user"] = name;
            peer["ip"] = endpoint;
            long long hs = 0;
            try { hs = stoll(handshake); } catch (...) { hs = 0; }
            peer["status"] = (hs > 0 && std::time(nullptr) - hs < 180) ? "on" : "off";
            peers.push_back(std::move(peer));
        }
        data["clients"] = std::move(peers);
        return crow::response{data};
    });
    CROW_ROUTE(app, "/api/wireguard/create").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::response res;
        auto params = req.get_body_params();
        std::string name = params.get("name");
        std::string ip   = params.get("ip");
        if (!is_valid_ipv4(ip))
            return crow::response(400, "Invalid IP address");
        std::string privkey = exec("wg genkey");
        privkey.erase(privkey.find_last_not_of('\n') + 1);
        std::string pubkey = exec("echo " + privkey + " | wg pubkey");
        pubkey.erase(pubkey.find_last_not_of('\n') + 1);
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db, "INSERT INTO wireguard_clients (name, public_key, private_key, ip) VALUES (?, ?, ?, ?);",
                           -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, pubkey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, privkey.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, std::string(params.get("ip")).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        exec("wg set wg0 peer " + pubkey + " allowed-ips " + params.get("ip") + "/32");
        exec("wg-quick save wg0");
        return res;
    });
    CROW_ROUTE(app, "/api/wireguard/delete").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::response res;
        sqlite3_stmt *stmt;
        auto params = req.get_body_params();
        std::string key = params.get("key");
        if (!is_valid_wg_key(key))
            return crow::response(400, "Invalid key");
        exec("wg set wg0 peer " + key + " remove");
        exec("wg-quick save wg0");
        sqlite3_prepare_v2(db, "DELETE FROM wireguard_clients WHERE public_key = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return res;
    });
    CROW_ROUTE(app, "/api/wireguard/start").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::json::wvalue data;
        auto params = req.get_body_params();
        exec("systemctl start wg-quick@wg0");
        data["success"] = wireguard_active();
        return crow::response{data};
    });
    CROW_ROUTE(app, "/api/wireguard/stop").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::json::wvalue data;
        auto params = req.get_body_params();
        exec("systemctl stop wg-quick@wg0");
        data["failure"] = wireguard_active();
        return crow::response{data};
    });
    CROW_ROUTE(app, "/api/wireguard/info").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::json::wvalue data;
        auto params = req.get_body_params();
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db, "SELECT private_key, ip FROM wireguard_clients WHERE name = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, std::string(params.get("name")).c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            return crow::response(404, "Client not found");
        }
        auto raw_pkey = sqlite3_column_text(stmt, 0);
        auto raw_ip   = sqlite3_column_text(stmt, 1);
        std::string prkey     = raw_pkey ? reinterpret_cast<const char*>(raw_pkey) : "";
        std::string client_ip = raw_ip   ? reinterpret_cast<const char*>(raw_ip)   : "";
        sqlite3_finalize(stmt);
        std::string server_pubkey = exec("wg show wg0 public-key");
        server_pubkey.erase(server_pubkey.find_last_not_of('\n') + 1);
        std::string server_ip = exec("curl -s ifconfig.me");
        server_ip.erase(server_ip.find_last_not_of('\n') + 1);
        std::string config =
                "[Interface]\n"
                "PrivateKey = " + prkey + "\n"
                "Address = " + client_ip + "/32\n"
                "DNS = 8.8.8.8\n\n"
                "[Peer]\n"
                "PublicKey = " + server_pubkey + "\n"
                "Endpoint = " + server_ip + ":51820\n"
                "AllowedIPs = 0.0.0.0/0\n";
        exec("echo '" + config + "' | qrencode -t PNG -o /tmp/qr.png");
        data["config"] = config;
        std::ifstream file("/tmp/qr.png", std::ios::binary);
        std::string png((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        data["qrcode"] = to_base64(png);
        return crow::response{data};
    });
    CROW_ROUTE(app, "/api/setup").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::response res;
        auto params = req.get_body_params();
        std::string username = params.get("username");
        std::string password = params.get("password");
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db, "INSERT INTO user (username, password_hash, ip) VALUES (?, ?, '');", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash_password(password).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return res;
    });
    CROW_ROUTE(app, "/api/change_credentials").methods(crow::HTTPMethod::POST)([](const crow::request &req) {
        crow::response res;
        auto params = req.get_body_params();
        std::string username = params.get("username");
        std::string password = params.get("password");
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db, "UPDATE user SET username = ?, password_hash = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, hash_password(password).c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return res;
    });
    app.port(8080).multithreaded().run();
    sqlite3_close(db);
    return 0;
}
