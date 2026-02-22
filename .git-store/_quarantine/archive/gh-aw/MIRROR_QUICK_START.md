# ⚡ Швидкий старт - GitHub Mirror

## 🚀 За 5 хвилин до робочого дзеркалювання

### Крок 1: Запустіть тестовий скрипт

```bash
./test_mirror_setup.sh
```

Або автоматичний режим:

```bash
./test_mirror_setup.sh --auto
```

---

## 📝 Мінімальний набір команд

### 1️⃣ Генерація SSH ключа

```bash
ssh-keygen -t ed25519 -C "github-actions-mirror" -f ~/.ssh/github_mirror_key -N ""
```

### 2️⃣ Копіювання публічного ключа

```bash
cat ~/.ssh/github_mirror_key.pub
```

**Додайте цей ключ:**
- Source repo: https://github.com/vdykimppua/share-sweet-brains/settings/keys (БЕЗ write access)
- Target repo: https://github.com/maxfraieho/garden-bloom/settings/keys (З write access ✅)

### 3️⃣ Копіювання приватного ключа для Secret

```bash
cat ~/.ssh/github_mirror_key
```

Додайте як Secret `SSH_PRIVATE_KEY` тут:
https://github.com/vdykimppua/share-sweet-brains/settings/secrets/actions

### 4️⃣ Генерація SSH_KNOWN_HOSTS

```bash
ssh-keyscan -H github.com
```

Додайте як Secret `SSH_KNOWN_HOSTS` тут:
https://github.com/vdykimppua/share-sweet-brains/settings/secrets/actions

### 5️⃣ Push workflow файлу

```bash
git add .github/workflows/mirror.yml
git commit -m "Add GitHub Actions mirror workflow"
git push origin master
```

### 6️⃣ Перевірка виконання

Відкрийте: https://github.com/vdykimppua/share-sweet-brains/actions

---

## ✅ Швидка перевірка синхронізації

```bash
# Перевірка останнього коміту в source
curl -s https://api.github.com/repos/vdykimppua/share-sweet-brains/commits/master | grep -o '"sha": "[^"]*"' | head -1

# Перевірка останнього коміту в target
curl -s https://api.github.com/repos/maxfraieho/garden-bloom/commits/master | grep -o '"sha": "[^"]*"' | head -1
```

Якщо SHA співпадають - дзеркалювання працює! ✅

---

## 🧪 Швидкий тест

```bash
# Створити тестовий коміт
echo "Test $(date)" > mirror_test.txt
git add mirror_test.txt
git commit -m "Test: Mirror verification"
git push origin master

# Почекати 30-60 секунд, потім перевірити target репозиторій
```

---

## 🔗 Корисні посилання

- **Source repo Actions**: https://github.com/vdykimppua/share-sweet-brains/actions
- **Target repo**: https://github.com/maxfraieho/garden-bloom
- **Deploy Keys (source)**: https://github.com/vdykimppua/share-sweet-brains/settings/keys
- **Deploy Keys (target)**: https://github.com/maxfraieho/garden-bloom/settings/keys
- **Secrets**: https://github.com/vdykimppua/share-sweet-brains/settings/secrets/actions

---

## ❓ Troubleshooting одним рядком

```bash
# Перевірка SSH з'єднання
ssh -T git@github.com

# Перевірка YAML синтаксису workflow
python3 -c "import yaml; print('✅ Valid' if yaml.safe_load(open('.github/workflows/mirror.yml')) else '❌ Invalid')"

# Клонування target для перевірки
git clone git@github.com:maxfraieho/garden-bloom.git /tmp/check-mirror && cd /tmp/check-mirror && git log --oneline -5
```

---

## 📖 Детальна документація

Дивіться повну документацію: `GITHUB_MIRROR_SETUP.md`

**Успіхів! 🚀**
