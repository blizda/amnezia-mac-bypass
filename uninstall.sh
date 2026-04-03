#!/bin/bash
echo "Удаление bypass..."
sudo launchctl unload -w /Library/LaunchDaemons/com.local.bypass.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.local.bypass.plist
sudo rm -rf /opt/bypass
sudo networksetup -setdnsservers Wi-Fi Empty
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
echo "Удалено. DNS возвращен на настройки по умолчанию."
