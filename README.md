# 🛡️ CyberGuard Telegram Bot

Бот для кибербезопасности с анализом ссылок, файлов, проверкой паролей и защитой приватности.

---

## 📦 Структура проекта

```
telegram_bot/
├── bot.py           # Основной код бота
├── wsgi.py          # WSGI-точка входа для gunicorn
├── requirements.txt # Зависимости Python
├── Procfile         # Команда запуска для Render
└── README.md        # Эта инструкция
```

---

## ⚙️ Настройка перед деплоем

### 1. Получи токены

| Что | Где получить |
|-----|-------------|
| `BOT_TOKEN` | [@BotFather](https://t.me/BotFather) в Telegram |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com) → Account → API Key |
| `WEBHOOK_URL` | URL твоего приложения на Render (см. ниже) |

---

## 🚀 Деплой на Render (бесплатно)

### Шаг 1 — Загрузи на GitHub
1. Создай новый репозиторий на [github.com](https://github.com)
2. Загрузи все файлы из этой папки

### Шаг 2 — Создай Web Service на Render
1. Зайди на [render.com](https://render.com) и зарегистрируйся
2. Нажми **New → Web Service**
3. Подключи свой GitHub репозиторий
4. Настройки:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --worker-class gthread --workers 1 --threads 4 wsgi:flask_app`

### Шаг 3 — Переменные окружения (Environment Variables)
В разделе **Environment** добавь:

```
BOT_TOKEN=твой_токен_от_BotFather
VIRUSTOTAL_API_KEY=твой_ключ_от_virustotal
WEBHOOK_URL=https://имя-твоего-сервиса.onrender.com
```

> ⚠️ `WEBHOOK_URL` — это URL который Render даст после деплоя. 
> Сначала задеплой, потом обнови эту переменную.

### Шаг 4 — Активируй вебхук
После деплоя открой в браузере:
```
https://твой-сервис.onrender.com/set_webhook
```
Должен появиться ответ с подтверждением.

---

## 🔧 Локальный запуск (для тестов)

```bash
# Установи зависимости
pip install -r requirements.txt

# Задай переменные окружения
export BOT_TOKEN="твой_токен"
export VIRUSTOTAL_API_KEY="твой_ключ"
export WEBHOOK_URL="https://твой-ngrok.io"  # используй ngrok для локального теста

# Запусти
python bot.py
```

---

## 🤖 Функционал бота

| Раздел | Описание |
|--------|----------|
| 🔍 Анализ ссылок | Проверка URL через VirusTotal (70+ антивирусов) |
| 📁 Анализ файлов | Проверка SHA256-хэша файла через VirusTotal |
| 🔒 Приватность | Инструкция + ссылка на teletype.in |
| 🔑 Password | Анализ сложности + проверка по HIBP (утечки) |
| 🕵️ Защита от OSINT | Инструкция по защите личных данных |

---

## 📝 Лицензия

MIT — свободное использование.
