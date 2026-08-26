# QR Login Manager (резервные копии)

Многоязычная утилита для генерации, хранения и управления резервными кодами двухфакторной аутентификации (2FA).  
Резервные коды шифруются и сохраняются в файл, а также могут быть экспортированы в QR-код для печати или восстановления.

## Особенности
- Генерация случайных резервных кодов (буквы + цифры) заданной длины и количества.
- Шифрование данных (AES-GCM) с использованием пароля для безопасного хранения.
- Дешифровка и просмотр сохранённых кодов.
- Экспорт кодов в QR-код (PNG) для удобного восстановления.
- Проверка наличия кода в сохранённом списке.
- Поддержка импорта/экспорта в JSON (незашифрованный) для миграции.
- Цветной вывод в терминале (где поддерживается).
- Полностью консольное управление через аргументы командной строки.

## Установка и запуск
Для каждого языка требуются соответствующие инструменты и зависимости.

### Запуск на разных языках

1. **Python**  
   Установка: `pip install cryptography qrcode[pil] pillow colorama`  
   Запуск: `python qr_login_manager.py --generate 10 --output backup.json --password mypass`

2. **JavaScript (Node.js)**  
   Установка: `npm install commander qrcode crypto-js chalk`  
   Запуск: `node qr_login_manager.js --generate 10 --output backup.json --password mypass`

3. **Go**  
   Установка: `go get github.com/skip2/go-qrcode`  
   Запуск: `go run qr_login_manager.go --generate 10 --output backup.json --password mypass`

4. **Rust**  
   Добавьте `clap`, `rand`, `aes-gcm`, `qrcode-generator`, `serde`, `serde_json` в `Cargo.toml`.  
   Запуск: `cargo run -- --generate 10 --output backup.json --password mypass`

5. **Java**  
   Используйте библиотеки: `org.bouncycastle`, `com.google.zxing`, `com.google.gson`.  
   Сборка: `javac -cp bcprov-jdk15on.jar:core.jar:javase.jar:gson.jar QRLoginManager.java`  
   Запуск: `java -cp .;bcprov-jdk15on.jar;core.jar;javase.jar;gson.jar QRLoginManager --generate 10 --output backup.json --password mypass`

6. **C# (.NET Core)**  
   Установка: `dotnet add package Newtonsoft.Json` и `System.Security.Cryptography` и `QRCoder`.  
   Запуск: `dotnet run -- --generate 10 --output backup.json --password mypass`

7. **C++ (Linux)**  
   Требуется OpenSSL, libqrencode, nlohmann/json.  
   Сборка: `g++ -std=c++11 -o qr_login_manager qr_login_manager.cpp -lssl -lcrypto -lqrencode -lpng -ljsoncpp`  
   Запуск: `./qr_login_manager --generate 10 --output backup.json --password mypass`

8. **Kotlin (JVM)**  
   Используйте Bouncy Castle, ZXing, Gson.  
   Сборка: `kotlinc -cp bcprov-jdk15on.jar:core.jar:javase.jar:gson.jar QRLoginManager.kt`  
   Запуск: `kotlin -cp .;bcprov-jdk15on.jar;core.jar;javase.jar;gson.jar QRLoginManagerKt --generate 10`

## Использование

Общие аргументы (везде, где поддерживается):

- `--generate <count>` – сгенерировать указанное количество резервных кодов (по умолчанию 10).
- `--output <file>` – файл для сохранения (шифрованный JSON).
- `--password <pwd>` – пароль для шифрования/дешифрования.
- `--list <file>` – показать коды из файла (требуется пароль).
- `--qr <file>` – создать QR-код из файла (PNG) – требуется пароль.
- `--check <code>` – проверить, есть ли код в файле (требуется пароль).
- `--export-json <file>` – экспортировать расшифрованные данные в незашифрованный JSON.
- `--import-json <file>` – импортировать из незашифрованного JSON и сохранить с паролем.

Пример (Python):
```bash
python qr_login_manager.py --generate 20 --output mybackup.enc --password secret123
python qr_login_manager.py --list mybackup.enc --password secret123
python qr_login_manager.py --qr mybackup.enc --password secret123 --output qrcodes.png
Структура репозитория
text
/
├── README.md
├── qr_login_manager.py
├── qr_login_manager.js
├── qr_login_manager.go
├── qr_login_manager.rs
├── QRLoginManager.java
├── QRLoginManager.cs
├── qr_login_manager.cpp
└── QRLoginManager.kt
Лицензия
MIT
