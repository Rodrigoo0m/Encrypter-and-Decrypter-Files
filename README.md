# Encrypter and Decrypter.py

This Python script provides functionality to encrypt and describe files using AES encryption with CBC mode and PBKDF2 key derivation.

## Functionalities
- **Encryption:** Encryption of a specified file using AES encryption with CBC mode.
- **Decryption:** Decrypts a previously encrypted file using a specified password.

## Requirements
-Python 3.x
- `cryptography` library (`pip install cryptography`)

## Usage
1. **Encryption:**
   - Run the script and choose 'E' to encrypt a file.
   - Enter the path of the file to be encrypted.
   - Enter a password (key) for encryption.

2. **Description:**
   - Run the script and choose 'D' to describe a file.
   - Enter the path of the encrypted file.
   - Enter the password used during encryption.

## How it works
- The script uses AES encryption in CBC mode (`Cipher` from `cryptography.hazmat.primitives.ciphers`).
- Password-based key derivation is performed using PBKDF2 with SHA-256.
- File padding is handled with PKCS7 padding.
- Salt and IV (Initialization Vector) are randomly generated for each encryption operation.
- Decryption retrieves the salt and IV of the encrypted file and uses them together with the password to describe the file.

##Security
- The script implements best practices for file encryption:
  - Use of AES encryption, a strong symmetric encryption algorithm.
  - PBKDF2 with SHA-256 for key derivation, improving password security.
  - CBC mode with random IV to mitigate known text attacks.
  - PKCS7 padding to ensure correct block sizes for AES.

## Comments
--securely store and manage your password/key used for encryption and description.
- Keep your dependencies updated for security fixes.

----------------------------------------------------------------------------------------------------------------------------------

# Encrypter and Decrypter.py

Este script em Python oferece funcionalidade para criptografar e descriptografar arquivos usando criptografia AES com modo CBC e derivação de chave PBKDF2.

## Funcionalidades
- **Criptografia:** Criptografa um arquivo especificado usando criptografia AES com modo CBC.
- **Descriptografia:** Descriptografa um arquivo previamente criptografado usando a senha especificada.

## Requisitos
- Python 3.x
- Biblioteca `cryptography` (`pip install cryptography`)

## Uso
1. **Criptografia:**
   - Execute o script e escolha 'E' para criptografar um arquivo.
   - Insira o caminho do arquivo a ser criptografado.
   - Insira uma senha (chave) para a criptografia.

2. **Descriptografia:**
   - Execute o script e escolha 'D' para descriptografar um arquivo.
   - Insira o caminho do arquivo criptografado.
   - Insira a senha utilizada durante a criptografia.

## Como Funciona
- O script utiliza criptografia AES em modo CBC (`Cipher` da `cryptography.hazmat.primitives.ciphers`).
- Derivação de chave baseada em senha é realizada usando PBKDF2 com SHA-256.
- O preenchimento do arquivo é tratado com preenchimento PKCS7.
- Sal e IV (Vetor de Inicialização) são gerados aleatoriamente para cada operação de criptografia.
- A descriptografia recupera o sal e o IV do arquivo criptografado e os utiliza junto com a senha para descriptografar o arquivo.

## Segurança
- O script implementa práticas recomendadas para criptografia de arquivos:
  - Uso de criptografia AES, um algoritmo de criptografia simétrica forte.
  - PBKDF2 com SHA-256 para derivação de chave, melhorando a segurança da senha.
  - Modo CBC com IV aleatório para mitigar ataques de texto conhecido.
  - Preenchimento PKCS7 para garantir tamanhos de bloco corretos para AES.

## Observações
- Certifique-se de armazenar e gerenciar sua senha/chave usada para criptografia e descriptografia de forma segura.
- Mantenha suas dependências atualizadas para correções de segurança.

