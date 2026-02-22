#!/bin/bash

# ========================================
# Скрипт для тестування налаштування
# GitHub Actions Mirror
# ========================================

set -e

COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RED='\033[0;31m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

echo -e "${COLOR_BLUE}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║   GitHub Actions Mirror - Testing Script              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo -e "${COLOR_RESET}"

# ========================================
# Функція 1: Генерація SSH ключа
# ========================================
generate_ssh_key() {
    echo -e "\n${COLOR_YELLOW}[1/7] Генерація SSH ключа...${COLOR_RESET}"

    if [ -f ~/.ssh/github_mirror_key ]; then
        echo -e "${COLOR_YELLOW}⚠️  SSH ключ вже існує. Хочете перезаписати? (y/N)${COLOR_RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            echo -e "${COLOR_GREEN}✅ Використовуємо існуючий ключ${COLOR_RESET}"
            return
        fi
    fi

    ssh-keygen -t ed25519 -C "github-actions-mirror" -f ~/.ssh/github_mirror_key -N ""

    echo -e "${COLOR_GREEN}✅ SSH ключ успішно згенеровано${COLOR_RESET}"
    echo -e "   Приватний ключ: ~/.ssh/github_mirror_key"
    echo -e "   Публічний ключ: ~/.ssh/github_mirror_key.pub"
}

# ========================================
# Функція 2: Відображення публічного ключа
# ========================================
show_public_key() {
    echo -e "\n${COLOR_YELLOW}[2/7] Публічний SSH ключ для Deploy Keys:${COLOR_RESET}"
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    cat ~/.ssh/github_mirror_key.pub
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "\n${COLOR_GREEN}📋 Скопіюйте цей ключ та додайте його як Deploy Key в обох репозиторіях:${COLOR_RESET}"
    echo -e "   1. Source (vdykimppua/share-sweet-brains) - БЕЗ write access"
    echo -e "   2. Target (maxfraieho/garden-bloom) - З write access ✅"
    echo -e "\nНатисніть Enter після додавання ключів на GitHub..."
    read -r
}

# ========================================
# Функція 3: Відображення приватного ключа
# ========================================
show_private_key() {
    echo -e "\n${COLOR_YELLOW}[3/7] Приватний SSH ключ для GitHub Secrets:${COLOR_RESET}"
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    cat ~/.ssh/github_mirror_key
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "\n${COLOR_GREEN}📋 Скопіюйте ВЕСЬ вміст (включно з BEGIN/END рядками)${COLOR_RESET}"
    echo -e "   Додайте як Secret з назвою: ${COLOR_YELLOW}SSH_PRIVATE_KEY${COLOR_RESET}"
    echo -e "\nНатисніть Enter після додавання Secret на GitHub..."
    read -r
}

# ========================================
# Функція 4: Генерація SSH_KNOWN_HOSTS
# ========================================
generate_known_hosts() {
    echo -e "\n${COLOR_YELLOW}[4/7] Генерація SSH_KNOWN_HOSTS...${COLOR_RESET}"

    ssh-keyscan -H github.com > /tmp/github_known_hosts.txt 2>/dev/null

    echo -e "${COLOR_GREEN}✅ SSH_KNOWN_HOSTS згенеровано${COLOR_RESET}"
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    cat /tmp/github_known_hosts.txt
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "\n${COLOR_GREEN}📋 Скопіюйте вміст вище${COLOR_RESET}"
    echo -e "   Додайте як Secret з назвою: ${COLOR_YELLOW}SSH_KNOWN_HOSTS${COLOR_RESET}"
    echo -e "\nНатисніть Enter після додавання Secret на GitHub..."
    read -r
}

# ========================================
# Функція 5: Перевірка workflow файлу
# ========================================
check_workflow_file() {
    echo -e "\n${COLOR_YELLOW}[5/7] Перевірка workflow файлу...${COLOR_RESET}"

    if [ ! -f .github/workflows/mirror.yml ]; then
        echo -e "${COLOR_RED}❌ Файл .github/workflows/mirror.yml не знайдено!${COLOR_RESET}"
        exit 1
    fi

    echo -e "${COLOR_GREEN}✅ Workflow файл знайдено${COLOR_RESET}"

    # Перевірка синтаксису YAML (базова)
    if command -v python3 &> /dev/null; then
        python3 -c "import yaml; yaml.safe_load(open('.github/workflows/mirror.yml'))" 2>/dev/null && \
            echo -e "${COLOR_GREEN}✅ YAML синтаксис валідний${COLOR_RESET}" || \
            echo -e "${COLOR_RED}⚠️  Можливі помилки в YAML синтаксисі${COLOR_RESET}"
    fi
}

# ========================================
# Функція 6: Тестовий коміт
# ========================================
create_test_commit() {
    echo -e "\n${COLOR_YELLOW}[6/7] Створення тестового коміту...${COLOR_RESET}"

    # Створення тестового файлу
    echo "Mirror test at $(date)" > .mirror_test_$(date +%s).txt

    git add .github/workflows/mirror.yml .mirror_test_*.txt 2>/dev/null || true

    echo -e "\n${COLOR_GREEN}Готово до коміту. Виконати push зараз? (y/N)${COLOR_RESET}"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        git commit -m "feat: Add GitHub Actions workflow for automatic repository mirroring

- Auto-mirror to maxfraieho/garden-bloom on push/create/delete events
- SSH authentication with deploy keys
- Concurrency control to prevent parallel mirroring jobs
- Test file for mirror verification"

        echo -e "\n${COLOR_YELLOW}Push до source репозиторію? (y/N)${COLOR_RESET}"
        read -r push_response

        if [[ "$push_response" =~ ^[Yy]$ ]]; then
            git push origin $(git branch --show-current)
            echo -e "${COLOR_GREEN}✅ Зміни відправлені. GitHub Actions має запуститись автоматично!${COLOR_RESET}"
        fi
    else
        echo -e "${COLOR_YELLOW}⚠️  Коміт пропущено. Виконайте вручну:${COLOR_RESET}"
        echo -e "   git add .github/workflows/mirror.yml"
        echo -e "   git commit -m 'Add mirror workflow'"
        echo -e "   git push origin master"
    fi
}

# ========================================
# Функція 7: Інструкції з моніторингу
# ========================================
show_monitoring_info() {
    echo -e "\n${COLOR_YELLOW}[7/7] Моніторинг та перевірка:${COLOR_RESET}"
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "\n${COLOR_GREEN}🔍 Перевірка виконання GitHub Actions:${COLOR_RESET}"
    echo -e "   https://github.com/vdykimppua/share-sweet-brains/actions"

    echo -e "\n${COLOR_GREEN}🔍 Перевірка target репозиторію:${COLOR_RESET}"
    echo -e "   https://github.com/maxfraieho/garden-bloom"

    echo -e "\n${COLOR_GREEN}📝 Команди для локальної перевірки:${COLOR_RESET}"
    echo -e "   ${COLOR_YELLOW}# Клонувати target репозиторій${COLOR_RESET}"
    echo -e "   git clone git@github.com:maxfraieho/garden-bloom.git /tmp/garden-bloom"
    echo -e ""
    echo -e "   ${COLOR_YELLOW}# Перевірити останні коміти${COLOR_RESET}"
    echo -e "   cd /tmp/garden-bloom && git log --oneline -10"
    echo -e ""
    echo -e "   ${COLOR_YELLOW}# Порівняти з source репозиторієм${COLOR_RESET}"
    echo -e "   git remote add source git@github.com:vdykimppua/share-sweet-brains.git"
    echo -e "   git fetch source"
    echo -e "   git diff source/master master"

    echo -e "\n${COLOR_GREEN}✅ Якщо diff порожній - дзеркалювання працює ідеально!${COLOR_RESET}"
    echo -e "${COLOR_BLUE}═══════════════════════════════════════════════════════${COLOR_RESET}"
}

# ========================================
# Головне меню
# ========================================
main_menu() {
    echo -e "\n${COLOR_YELLOW}Оберіть опцію:${COLOR_RESET}"
    echo "  1) Повне налаштування (всі кроки)"
    echo "  2) Тільки генерація SSH ключів"
    echo "  3) Показати публічний ключ"
    echo "  4) Показати приватний ключ"
    echo "  5) Генерувати SSH_KNOWN_HOSTS"
    echo "  6) Перевірити workflow файл"
    echo "  7) Створити тестовий коміт"
    echo "  8) Показати інструкції з моніторингу"
    echo "  9) Вийти"
    echo -e "\n${COLOR_YELLOW}Ваш вибір (1-9):${COLOR_RESET} "
    read -r choice

    case $choice in
        1)
            generate_ssh_key
            show_public_key
            show_private_key
            generate_known_hosts
            check_workflow_file
            create_test_commit
            show_monitoring_info
            ;;
        2) generate_ssh_key ;;
        3) show_public_key ;;
        4) show_private_key ;;
        5) generate_known_hosts ;;
        6) check_workflow_file ;;
        7) create_test_commit ;;
        8) show_monitoring_info ;;
        9)
            echo -e "${COLOR_GREEN}До побачення!${COLOR_RESET}"
            exit 0
            ;;
        *)
            echo -e "${COLOR_RED}Невірний вибір. Спробуйте ще раз.${COLOR_RESET}"
            main_menu
            ;;
    esac
}

# ========================================
# Запуск скрипту
# ========================================
if [ "$1" == "--auto" ]; then
    # Автоматичний режим (всі кроки)
    generate_ssh_key
    show_public_key
    show_private_key
    generate_known_hosts
    check_workflow_file
    create_test_commit
    show_monitoring_info
else
    # Інтерактивний режим
    main_menu
fi

echo -e "\n${COLOR_GREEN}✅ Готово!${COLOR_RESET}\n"
