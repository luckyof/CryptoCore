# CryptoCore

CryptoCore — минималистический консольный криптографический провайдер для
шифрования и расшифрования файлов с помощью AES-128 в режиме ECB. Первый спринт
посвящён корректной обработке блоков, дополнению PKCS#7, двоичному файловому
вводу-выводу и предсказуемому интерфейсу командной строки.

> **Предупреждение о безопасности:** режим ECB раскрывает повторяющиеся шаблоны
> открытого текста и не подходит для защиты реальных данных. В этом проекте он
> реализован исключительно как учебная основа для более безопасных режимов из
> следующих спринтов.

## Требования

- Python 3.9 или новее;
- `pip`;
- [PyCryptodome](https://pycryptodome.readthedocs.io/) версии 3.20 или новее.

PyCryptodome предоставляет проверенный блочный примитив AES. CryptoCore
самостоятельно реализует обработку блоков ECB и дополнение PKCS#7.

## Установка

Создайте изолированное окружение и установите проект из его корневого каталога.

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

### Linux и macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

После установки проверьте доступность консольной команды:

```bash
cryptocore --help
```

## Использование

Ключ передаётся в виде ровно 32 шестнадцатеричных символов — это 16 байт,
необходимые для AES-128.

Шифрование файла:

```bash
cryptocore --algorithm aes --mode ecb --encrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input plaintext.txt --output ciphertext.bin
```

Расшифрование файла:

```bash
cryptocore --algorithm aes --mode ecb --decrypt \
  --key 000102030405060708090a0b0c0d0e0f \
  --input ciphertext.bin --output decrypted.txt
```

Параметры `--algorithm aes`, `--mode ecb`, `--key` и `--input` обязательны.
Также необходимо указать ровно один из флагов: `--encrypt` или `--decrypt`.
Если параметр `--output` отсутствует, CryptoCore добавляет к имени входного
файла расширение `.enc` при шифровании или `.dec` при расшифровании.

Ошибки аргументов, файловой системы и криптографических операций выводятся в
стандартный поток ошибок. При ошибке программа завершается с ненулевым кодом.

## Тестирование

После установки запустите полный набор тестов из корневого каталога проекта:

```bash
python -m unittest discover -s tests -v
```

Тесты проверяют пустые, короткие, выровненные по размеру блока, многоблочные и
двоичные входные данные; опубликованный тестовый вектор AES; работу PKCS#7;
неправильные ключи, шифротекст и дополнение; файловые ошибки; автоматическое
имя выходного файла и полный цикл обработки файла.

### Ручной приёмочный тест

```bash
printf "Проверка CryptoCore" > original.txt
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input original.txt --output encrypted.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input encrypted.bin --output decrypted.txt
cmp original.txt decrypted.txt
```

В Windows сравнить файлы побайтово можно так:

```powershell
fc.exe /b original.txt decrypted.txt
```

Отсутствие вывода `cmp` или сообщение `FC: no differences encountered`
означает, что файлы совпадают.

### Проверка совместимости с OpenSSL

CryptoCore использует стандартное дополнение PKCS#7, соответствующее поведению
`openssl enc` по умолчанию:

```bash
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.txt -out openssl.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input openssl.bin --output openssl-decrypted.txt
cmp plaintext.txt openssl-decrypted.txt
```

## Структура проекта

```text
src/cryptocore/
├── cli.py          # разбор аргументов и управление выполнением команды
├── file_io.py      # двоичные файловые операции
├── errors.py       # прикладные ошибки для вывода пользователю
└── modes/ecb.py    # реализация AES-128 ECB и PKCS#7
tests/              # модульные и интеграционные тесты
pyproject.toml      # конфигурация пакета, зависимостей и консольной команды
```
