#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <algorithm> // Для std::min

// Функция для генерации ECDH ключей
EC_KEY* generate_ecdh_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Используем кривую P-256
    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Ошибка генерации ECDH ключей" << std::endl;
        return nullptr;
    }
    return key;
}

// Функция для вычисления общего секретного ключа
std::vector<unsigned char> compute_shared_secret(EC_KEY *private_key, const EC_POINT *peer_public_key) {
    const EC_GROUP *group = EC_KEY_get0_group(private_key);
    if (!group) {
        std::cerr << "Ошибка получения группы из приватного ключа" << std::endl;
        return {};
    }

    int degree = EC_GROUP_get_degree(group);
    if (degree <= 0) {
        std::cerr << "Ошибка получения степени группы" << std::endl;
        return {};
    }

    size_t secret_len = (degree + 7) / 8;
    std::vector<unsigned char> secret(secret_len);

    int secret_size = ECDH_compute_key(secret.data(), secret.size(), peer_public_key, private_key, nullptr);
    if (secret_size <= 0) {
        std::cerr << "Ошибка вычисления общего секретного ключа" << std::endl;
        return {};
    }

    secret.resize(secret_size);
    return secret;
}

// Функция для шифрования данных по блокам с использованием AES
void aes_encrypt_blocks(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Ошибка создания контекста шифрования" << std::endl;
        return;
    }

    std::vector<unsigned char> iv(EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    RAND_bytes(iv.data(), iv.size());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Ошибка инициализации шифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len;
    int ciphertext_len;

    // Замер общего времени шифрования
    auto total_start = std::chrono::high_resolution_clock::now();

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "Ошибка шифрования данных" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        std::cerr << "Ошибка завершения шифрования" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    // Замер общего времени шифрования
    auto total_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_elapsed = total_end - total_start;
    std::cout << "Общее время шифрования: " << total_elapsed.count() << " секунд" << std::endl;

    EVP_CIPHER_CTX_free(ctx);

    // Запись зашифрованных данных в файл
    std::ofstream outfile("output.bin", std::ios::binary);
    outfile.write(reinterpret_cast<char*>(iv.data()), iv.size()); // Записываем IV в начало файла
    outfile.write(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    outfile.close();
}

int main() {
    // Генерация ключей для Alice и Bob
    EC_KEY *alice_key = generate_ecdh_key();
    EC_KEY *bob_key = generate_ecdh_key();

    // Получение публичных ключей
    const EC_POINT *alice_public = EC_KEY_get0_public_key(alice_key);
    const EC_POINT *bob_public = EC_KEY_get0_public_key(bob_key);

    // Вычисление общего секретного ключа
    std::vector<unsigned char> alice_secret = compute_shared_secret(alice_key, bob_public);
    std::vector<unsigned char> bob_secret = compute_shared_secret(bob_key, alice_public);

    // Проверка, что секретные ключи совпадают
    if (alice_secret != bob_secret) {
        std::cerr << "Секретные ключи не совпадают!" << std::endl;
        return 1;
    }

    // Чтение бинарного файла
    std::ifstream file("data.bin", std::ios::binary);
    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Шифрование данных по блокам
    aes_encrypt_blocks(plaintext, alice_secret);

    // Освобождение ресурсов
    EC_KEY_free(alice_key);
    EC_KEY_free(bob_key);

    std::cout << "Файл успешно зашифрован!" << std::endl;
    return 0;
}