# CryptoCore

CryptoCore — минималистический консольный криптографический провайдер для
шифрования и расшифрования файлов с помощью AES-128 в режимах ECB, CBC,
CFB-128, OFB и CTR. Реализованы первый и второй спринты.

> **Предупреждение о безопасности:** режим ECB раскрывает повторяющиеся шаблоны
> открытого текста и не подходит для защиты реальных данных. В этом проекте он
> реализован исключительно как учебная основа для более безопасных режимов из
> следующих спринтов.

## Требования

- Python 3.9 или новее;
- `pip`;
- [PyCryptodome](https://pycryptodome.readthedocs.io/) версии 3.20 или новее.

PyCryptodome предоставляет проверенный блочный примитив AES. CryptoCore
самостоятельно реализует логику всех пяти режимов и дополнение PKCS#7.

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

### Режимы и IV (спринт 2)

Параметр `--mode` принимает `ecb`, `cbc`, `cfb`, `ofb`, `ctr`.
ECB и CBC используют PKCS#7, включая дополнительный блок для данных кратной
16 байтам длины. CFB (сегмент 128 бит), OFB и CTR не используют дополнение
и сохраняют длину данных, включая пустые файлы и неполные последние блоки.
CTR использует весь 16-байтный IV как счётчик big-endian с прибавлением единицы
по модулю 2**128.

Для новых режимов при шифровании IV генерируется через `os.urandom(16)`.
Формат результата: `[16 байт IV][шифротекст]`. Ключ в файл не записывается.
При расшифровании без `--iv` заголовок извлекается автоматически.
При явном `--iv` весь входной файл считается шифротекстом **без заголовка**,
как в выводе OpenSSL. IV — ровно 32 hex-символа.
Передача `--iv` при шифровании или в режиме ECB считается ошибкой.

Пример PowerShell (замените `cbc` на любой другой новый режим):

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input original.txt --output encrypted.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input encrypted.bin --output decrypted.txt
fc.exe /b original.txt decrypted.txt
```

Для файла от OpenSSL:

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 000102030405060708090a0b0c0d0e0f --input openssl.bin --output decrypted.txt
```

Эти режимы не обеспечивают аутентификацию: неверный ключ или изменение
шифротекста не всегда обнаруживаются. Проверка padding не заменяет MAC.

### Автоматические проверки

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

Полный сценарий второго спринта проверяет CBC, CFB-128, OFB и CTR в обе стороны:
CryptoCore → OpenSSL и OpenSSL → CryptoCore. Он запускает CLI как отдельные
процессы для 9 размеров данных, извлекает IV из заголовка и сравнивает байты.
Временные файлы создаются в отдельном каталоге и автоматически удаляются.

```powershell
python -m unittest tests.test_modes.OpenSSLTests -v
```

OpenSSL ищется в PATH и в `C:/Program Files/Git/usr/bin/openssl.exe`.
Другой путь можно задать в PowerShell:

```powershell
$env:OPENSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
python -m unittest tests.test_modes.OpenSSLTests -v
```

Если OpenSSL отсутствует, тест отмечается как пропущенный (`skipped`).
Для приёмки совместимости требуется успешный запуск без пропуска.

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
└── modes/
    ├── ecb.py      # AES-128 ECB и PKCS#7
    └── feedback.py # CBC, CFB-128, OFB и CTR
tests/              # модульные и интеграционные тесты
pyproject.toml      # конфигурация пакета, зависимостей и консольной команды
```
