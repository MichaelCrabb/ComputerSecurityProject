// secure_chat.cpp (fully integrated nested dual-AES cascade with ciphertext/plaintext logging)

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <sstream>
#include <iomanip>     // for print_hex
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/sha.h>

constexpr int SALT_LEN    = 16;
constexpr int KEY_LEN     = 16;   // AES-128
constexpr int IV_LEN      = 16;
constexpr int PBKDF2_ITER = 100000;
constexpr int REKEY_AFTER = 100;

#ifdef _WIN32
  #define CLOSESOCK(s) closesocket(s)
#else
  #define CLOSESOCK(s) close(s)
#endif

// -----------------------------------------------------------------------------
// Helper: print a buffer as hex
// -----------------------------------------------------------------------------
void print_hex(const unsigned char* buf, size_t len) {
    std::ios oldState(nullptr);
    oldState.copyfmt(std::cout);
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        std::cout << std::setw(2) << (int)buf[i];
    std::cout.copyfmt(oldState);
}

// -----------------------------------------------------------------------------
// send/recv length-prefixed data
// -----------------------------------------------------------------------------
bool send_data(int sock, const unsigned char* data, size_t len) {
    uint32_t nlen = htonl((uint32_t)len);
    if (send(sock, &nlen, sizeof(nlen), 0) != sizeof(nlen)) return false;
    if (send(sock, data, len, 0) != (ssize_t)len) return false;
    return true;
}

bool recv_data(int sock, unsigned char*& data, size_t& len) {
    uint32_t nlen = 0;
    if (recv(sock, &nlen, sizeof(nlen), MSG_WAITALL) != sizeof(nlen)) return false;
    len = ntohl(nlen);
    data = (unsigned char*)malloc(len);
    if (!data) return false;
    if (recv(sock, data, len, MSG_WAITALL) != (ssize_t)len) {
        free(data);
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// PBKDF2 key derivation
// -----------------------------------------------------------------------------
bool derive_key(const std::string &pass, const unsigned char *salt, unsigned char *out_key) {
    return PKCS5_PBKDF2_HMAC_SHA1(
        pass.c_str(), pass.size(),
        salt, SALT_LEN,
        PBKDF2_ITER,
        KEY_LEN, out_key
    );
}

// -----------------------------------------------------------------------------
// AES-128-CBC encrypt / decrypt
// -----------------------------------------------------------------------------
bool aes_cbc_encrypt(const unsigned char *pt, int pt_len,
                     const unsigned char *key,
                     unsigned char *iv,
                     unsigned char *ct, int &ct_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (!RAND_bytes(iv, IV_LEN)) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }
    int len = 0;
    if (!EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) { EVP_CIPHER_CTX_free(ctx); return false; }
    ct_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ct + len, &len))      { EVP_CIPHER_CTX_free(ctx); return false; }
    ct_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_cbc_decrypt(const unsigned char *ct, int ct_len,
                     const unsigned char *key,
                     const unsigned char *iv,
                     unsigned char *pt, int &pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return false; }
    int len = 0;
    if (!EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len))          { EVP_CIPHER_CTX_free(ctx); return false; }
    pt_len = len;
    if (!EVP_DecryptFinal_ex(ctx, pt + len, &len))             { EVP_CIPHER_CTX_free(ctx); return false; }
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// -----------------------------------------------------------------------------
// Nested dual-AES cascade encrypt / decrypt
// -----------------------------------------------------------------------------
bool cascade_encrypt(const unsigned char *pt, int pt_len,
                     const unsigned char *key1, const unsigned char *key2,
                     unsigned char *out_hdr,            // iv1||iv2
                     unsigned char *out_ct, int &out_len) {
    int max1 = pt_len + EVP_MAX_BLOCK_LENGTH;
    std::vector<unsigned char> buf1(max1);
    unsigned char iv1[IV_LEN]; int len1 = 0;
    if (!aes_cbc_encrypt(pt, pt_len, key1, iv1, buf1.data(), len1)) return false;

    int max2 = len1 + EVP_MAX_BLOCK_LENGTH;
    std::vector<unsigned char> buf2(max2);
    unsigned char iv2[IV_LEN]; int len2 = 0;
    if (!aes_cbc_encrypt(buf1.data(), len1, key2, iv2, buf2.data(), len2)) return false;

    memcpy(out_hdr,        iv1,       IV_LEN);
    memcpy(out_hdr + IV_LEN, iv2,     IV_LEN);
    out_len = len2;
    memcpy(out_ct, buf2.data(), len2);
    return true;
}

bool cascade_decrypt(const unsigned char *in_hdr,
                     const unsigned char *in_ct, int in_len,
                     const unsigned char *key1, const unsigned char *key2,
                     unsigned char *out_pt, int &out_pt_len) {
    unsigned char iv1[IV_LEN], iv2[IV_LEN];
    memcpy(iv1, in_hdr,       IV_LEN);
    memcpy(iv2, in_hdr + IV_LEN, IV_LEN);

    std::vector<unsigned char> buf1(in_len + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0;
    if (!aes_cbc_decrypt(in_ct, in_len, key2, iv2, buf1.data(), len1)) return false;

    if (!aes_cbc_decrypt(buf1.data(), len1, key1, iv1, out_pt, out_pt_len)) return false;
    return true;
}

// -----------------------------------------------------------------------------
// Simple TCP server/client
// -----------------------------------------------------------------------------
int create_server(int port) {
    int serv = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(serv, (sockaddr*)&addr, sizeof(addr));
    listen(serv,1);
    std::cout<<"[Server] Listening on "<<port<<"...\n";
    int client = accept(serv, NULL, NULL);
    CLOSESOCK(serv);
    std::cout<<"[Server] Client connected.\n";
    return client;
}

int create_client(const std::string &ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(1);
    }
    std::cout<<"[Client] Connected to "<<ip<<":"<<port<<"\n";
    return sock;
}

// -----------------------------------------------------------------------------
// Diffie–Hellman fallback (legacy)
// -----------------------------------------------------------------------------
bool do_dh_exchange(int sock, unsigned char *shared_out, size_t &secret_len) {
    DH *dh = DH_get_2048_256();
    if (!dh) return false;
    if (!DH_generate_key(dh)) { DH_free(dh); return false; }
    const BIGNUM *pub = nullptr;
    DH_get0_key(dh, &pub, nullptr);
    int pub_len = BN_num_bytes(pub);
    std::vector<unsigned char> pubbin(pub_len);
    BN_bn2bin(pub, pubbin.data());
    send_data(sock, pubbin.data(), pubbin.size());

    unsigned char *peerbin = nullptr; size_t peerlen=0;
    recv_data(sock, peerbin, peerlen);
    BIGNUM *peer = BN_bin2bn(peerbin, peerlen, nullptr);
    free(peerbin);
    secret_len = DH_compute_key(shared_out, peer, dh);
    BN_free(peer);
    DH_free(dh);
    return secret_len>0;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        std::cerr<<"Usage: "<<argv[0]<<" [server|client] IP PORT PASS [--cascade]\n";
        return 1;
    }
    std::string mode = argv[1];
    std::string ip   = argv[2];
    int port         = std::stoi(argv[3]);
    std::string pass = argv[4];
    bool useCascade  = (argc==6 && std::string(argv[5])=="--cascade");

  #ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
  #endif
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

    int sock = (mode=="server")? create_server(port)
                              : create_client(ip, port);

    unsigned char salt[SALT_LEN];
    unsigned char session_key[KEY_LEN];

    // Key setup
    if (pass.empty()) {
        // DH fallback
        size_t secret_len=0;
        unsigned char shared[256];
        do_dh_exchange(sock, shared, secret_len);
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(shared, secret_len, hash);
        memcpy(salt, hash, SALT_LEN);
        derive_key("", salt, session_key);
        std::cout<<"[DH] Shared key established.\n";
    } else {
        if (mode=="client") {
            RAND_bytes(salt, SALT_LEN);
            send_data(sock, salt, SALT_LEN);
            unsigned char *echo; size_t elen;
            recv_data(sock, echo, elen); free(echo);
        } else {
            unsigned char *rs; size_t rlen;
            recv_data(sock, rs, rlen);
            memcpy(salt, rs, SALT_LEN); free(rs);
            send_data(sock, salt, SALT_LEN);
        }
        derive_key(pass, salt, session_key);
        std::cout<<"[Info] Key derived via PBKDF2.\n";
    }

    // Chat loop
    std::atomic<int> msg_count{0};
    fd_set fds;
    while (true) {
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(sock, &fds);
        if (select(sock+1, &fds, NULL, NULL, NULL) < 0) break;

        // ─── Send ───────────────────────────────────────────────────────────────
        if (FD_ISSET(0, &fds)) {
            std::string line;
            if (!std::getline(std::cin, line)) break;

            if (++msg_count >= REKEY_AFTER) {
                RAND_bytes(salt, SALT_LEN);
                send_data(sock, salt, SALT_LEN);
                unsigned char *echo; size_t elen;
                recv_data(sock, echo, elen); free(echo);
                derive_key(pass, salt, session_key);
                msg_count = 0;
                std::cout<<"[System] Key rotated.\n";
            }

            std::vector<unsigned char> outbuf;
            if (useCascade) {
                unsigned char subkey1[KEY_LEN], subkey2[KEY_LEN];
                derive_key(pass + "1", salt, subkey1);
                derive_key(pass + "2", salt, subkey2);

                int maxct = line.size() + EVP_MAX_BLOCK_LENGTH;
                outbuf.resize(IV_LEN*2 + maxct);
                int ctlen=0;
                cascade_encrypt(
                  (unsigned char*)line.c_str(), line.size(),
                  subkey1, subkey2,
                  outbuf.data(),
                  outbuf.data()+IV_LEN*2, ctlen
                );
                outbuf.resize(IV_LEN*2 + ctlen);
            } else {
                int maxct = line.size() + EVP_MAX_BLOCK_LENGTH;
                outbuf.resize(IV_LEN + maxct);
                unsigned char iv[IV_LEN]; int ctlen=0;
                aes_cbc_encrypt(
                  (unsigned char*)line.c_str(), line.size(),
                  session_key, iv,
                  outbuf.data()+IV_LEN, ctlen
                );
                memcpy(outbuf.data(), iv, IV_LEN);
                outbuf.resize(IV_LEN + ctlen);
            }

            // display sent ciphertext
            std::cout << "[Sent ciphertext] ";
            print_hex(outbuf.data(), outbuf.size());
            std::cout << "\n";

            send_data(sock, outbuf.data(), outbuf.size());
        }

        // ─── Receive ────────────────────────────────────────────────────────────
        if (FD_ISSET(sock, &fds)) {
            unsigned char *pkt = nullptr;
            size_t plen = 0;
            if (!recv_data(sock, pkt, plen)) { perror("recv"); break; }

            // display received ciphertext
            std::cout << "[Received ciphertext] ";
            print_hex(pkt, plen);
            std::cout << "\n";

            if (++msg_count >= REKEY_AFTER) {
                RAND_bytes(salt, SALT_LEN);
                send_data(sock, salt, SALT_LEN);
                unsigned char *echo; size_t elen;
                recv_data(sock, echo, elen); free(echo);
                derive_key(pass, salt, session_key);
                msg_count = 0;
                std::cout<<"[System] Key rotated.\n";
            }

            std::string out;
            if (useCascade) {
                unsigned char subkey1[KEY_LEN], subkey2[KEY_LEN];
                if (!derive_key(pass + "1", salt, subkey1) ||
                    !derive_key(pass + "2", salt, subkey2)) {
                    out = "[Error] Key derivation failed";
                } else {
                    int ctlen = plen - IV_LEN*2;
                    unsigned char *ctptr = pkt + IV_LEN*2;
                    std::vector<unsigned char> ptbuf(ctlen + EVP_MAX_BLOCK_LENGTH);
                    int ptlen = 0;
                    if (cascade_decrypt(
                          pkt,            // header = iv1||iv2
                          ctptr, ctlen,
                          subkey1, subkey2,
                          ptbuf.data(), ptlen
                        )) {
                        out.assign((char*)ptbuf.data(), ptlen);
                    } else {
                        out = "[Error] Decrypt failed";
                    }
                }
            } else {
                unsigned char iv[IV_LEN];
                memcpy(iv, pkt, IV_LEN);
                int ctlen = plen - IV_LEN;
                unsigned char *ctptr = pkt + IV_LEN;
                std::vector<unsigned char> ptbuf(ctlen + EVP_MAX_BLOCK_LENGTH);
                int ptlen=0;
                if (aes_cbc_decrypt(
                      ctptr, ctlen, session_key, iv,
                      ptbuf.data(), ptlen
                    )) {
                    out.assign((char*)ptbuf.data(), ptlen);
                } else {
                    out = "[Error] Decrypt failed";
                }
            }

            // display decrypted plaintext
            std::cout << "[Decrypted plaintext] " << out << "\n";

            free(pkt);
        }
    }

    CLOSESOCK(sock);
  #ifdef _WIN32
    WSACleanup();
  #endif
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}