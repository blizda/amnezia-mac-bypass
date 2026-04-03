#!/bin/bash

# --- НАСТРОЙКИ ---
RAW_GITHUB_URL="https://raw.githubusercontent.com/blizda/amnezia-mac-bypass/main/bypass.py"

PLIST_PATH="/Library/LaunchDaemons/com.local.bypass.plist"
SCRIPT_DIR="/opt/bypass"
SCRIPT_PATH="${SCRIPT_DIR}/bypass.py"

# Цвета для красивого вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}  Установка DNS Route Injector (Split DNS)  ${NC}"
echo -e "${GREEN}==============================================${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Ошибка: Скрипт нужно запускать с правами sudo.${NC}"
  echo -e "${YELLOW}Пожалуйста, выполните команду: sudo bash $0${NC}"
  exit 1
fi

echo -e "\n${YELLOW}[*] Установка зависимостей Python...${NC}"
python -m pip install requests dnslib --break-system-packages > /dev/null 2>&1 || python3 -m pip install requests dnslib > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Зависимости установлены.${NC}"
else
    echo -e "${RED}[!] Ошибка при установке библиотек. Убедитесь, что установлен pip.${NC}"
fi

echo -e "\n${YELLOW}[*] Скачивание основного скрипта с GitHub...${NC}"
mkdir -p "$SCRIPT_DIR"

curl -sL "$RAW_GITHUB_URL" -o "$SCRIPT_PATH"
if [ -s "$SCRIPT_PATH" ]; then
    echo -e "${GREEN}[+] Скрипт успешно скачан.${NC}"
else
    echo -e "${RED}[!] Ошибка скачивания! Проверьте доступность скрипта на GitHub.${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[*] Создание системной службы...${NC}"
cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.bypass</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>${SCRIPT_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/bypass.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/bypass.log</string>
</dict>
</plist>
EOF
echo -e "${GREEN}[+] Служба com.local.bypass создана.${NC}"

echo -e "\n${YELLOW}[*] Настройка прав доступа...${NC}"
chown -R root:wheel "$SCRIPT_DIR"
chmod 755 "$SCRIPT_PATH"
chown root:wheel "$PLIST_PATH"
chmod 644 "$PLIST_PATH"
echo -e "${GREEN}[+] Права доступа настроены.${NC}"

echo -e "\n${YELLOW}[*] Запуск демона...${NC}"
launchctl unload -w "$PLIST_PATH" 2>/dev/null
launchctl load -w "$PLIST_PATH"

echo -e "\n${GREEN}==============================================${NC}"
echo -e "${GREEN}Установка успешно завершена! 🚀${NC}"
echo -e "${YELLOW}Следить за логами работы можно командой:${NC}"
echo -e "tail -f /var/log/bypass.log"
echo -e "${GREEN}==============================================${NC}"
