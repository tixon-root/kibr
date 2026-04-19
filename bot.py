import os
import re
import math
import hashlib
import requests
import asyncio
from flask import Flask, request
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes
)

# ─── CONFIG ───────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VT_API_KEY_HERE")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://your-app.onrender.com")

# ─── FLASK APP ──────────────────────────────────────────────────────────
flask_app = Flask(__name__)
application = Application.builder().token(BOT_TOKEN).build()

loop = None

# ─── TEXTS ───────────────────────────────────────────────────────────
TEXT_START = (
    "Привет! Я помогу тебе проверить ссылки, файлы и пароли.\n\n"
    "Выбери что нужно:"
)

TEXT_ANALYZE_MENU = "Выбери что проверить:"

TEXT_URL_INSTRUCTIONS = (
    "Отправь ссылку, и я проверю её через VirusTotal.\n\n"
    "Проверяется: репутация домена, SSL, фишинг и редиректы.\n\n"
    "Пример: https://example.com"
)

TEXT_FILE_INSTRUCTIONS = (
    "Отправь файл документом (не фото).\n\n"
    "Поддерживаю: exe, dll, pdf, zip, rar, apk и т.д.\n"
    "Лимит: 20 МБ\n\n"
    "Проверю через SHA256 по базе VirusTotal."
)

TEXT_PRIVACY = (
    "Полная инструкция по защите данных и анонимности.\n"
    "Узнай как защитить себя от деанонимизации."
)

TEXT_OSINT = (
    "OSINT — это сбор инфы о тебе из открытых источников.\n\n"
    "Как защититься:\n"
    "• Скрывай личные данные в соцсетях\n"
    "• Используй разные ники везде\n"
    "• Удаляй EXIF с фото перед публикацией\n"
    "• Отдельный email для регистраций\n"
    "• Проверь себя на haveibeenpwned.com"
)

TEXT_PASSWORD_PROMPT = (
    "Отправь пароль, я проверю:\n"
    "• Сложность\n"
    "• Наличие в утечках (HIBP)\n"
    "• Даю рекомендации\n\n"
    "Пароль не сохраняется, используется только SHA1-хэш."
)

# ─── KEYBOARDS ─────────────────────────────────────────────────────────

def kb_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 Проверить ссылку", callback_data="analyze_url")],
        [InlineKeyboardButton("📁 Проверить файл", callback_data="analyze_file")],
        [InlineKeyboardButton("🔑 Пароль", callback_data="password")],
        [InlineKeyboardButton("🔒 Приватность", callback_data="privacy")],
        [InlineKeyboardButton("🕵️ OSINT", callback_data="osint")],
    ])

def kb_back_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("← Главное меню", callback_data="back_main")]
    ])

# ─── HELPERS ──────────────────────────────────────────────────────────

def check_password_strength(password: str) -> dict:
    score = 0
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("Минимум 8 символов")

    if len(password) >= 12:
        score += 1
    elif len(password) >= 8:
        tips.append("Лучше 12+ символов")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        tips.append("Добавь заглавные буквы (A-Z)")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        tips.append("Добавь строчные буквы (a-z)")

    if re.search(r'\d', password):
        score += 1
    else:
        tips.append("Добавь цифры (0-9)")

    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password):
        score += 1
    else:
        tips.append("Добавь спецсимволы (!@#$ и т.д.)")

    common = ["password", "123456", "qwerty", "abc123", "letmein",
              "admin", "welcome", "monkey", "dragon", "master"]
    if password.lower() in common:
        score = 0
        tips.insert(0, "⚠️ Это один из самых популярных паролей!")

    if score <= 2:
        level = "🔴 Очень слабый"
    elif score <= 3:
        level = "🟠 Слабый"
    elif score == 4:
        level = "🟡 Нормальный"
    elif score == 5:
        level = "🟢 Хороший"
    else:
        level = "✅ Отличный"

    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    entropy = round(len(password) * math.log2(charset), 1) if charset else 0

    return {"score": score, "level": level, "tips": tips, "entropy": entropy}


def check_hibp(password: str) -> tuple:
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
            headers={"Add-Padding": "true"}
        )
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return True, int(count)
        return False, 0
    except Exception:
        return None, 0


def analyze_url_vt(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        return {"error": "API ключ не настроен"}

    import base64
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if r.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=10
            )
            return {"status": "submitted", "message": "Отправлена на анализ, попробуй через 30 сек"}

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = sum(stats.values())

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "total": total,
            "reputation": data.get("reputation", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def analyze_file_vt(file_hash: str) -> dict:
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        return {"error": "API ключ не настроен"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers, timeout=10
        )
        if r.status_code == 404:
            return {"not_found": True}

        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "total": sum(stats.values()),
            "name": data.get("meaningful_name", "unknown"),
        }
    except Exception as e:
        return {"error": str(e)}

# ─── HANDLERS ──────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text(
        TEXT_START, parse_mode="HTML", reply_markup=kb_main()
    )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "back_main":
        context.user_data.clear()
        await query.edit_message_text(TEXT_START, parse_mode="HTML", reply_markup=kb_main())

    elif data == "analyze_url":
        context.user_data["mode"] = "url"
        await query.edit_message_text(
            TEXT_URL_INSTRUCTIONS, parse_mode="HTML", reply_markup=kb_back_main()
        )

    elif data == "analyze_file":
        context.user_data["mode"] = "file"
        await query.edit_message_text(
            TEXT_FILE_INSTRUCTIONS, parse_mode="HTML", reply_markup=kb_back_main()
        )

    elif data == "privacy":
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("Читать", url="https://teletype.in/@imperia_iot/infosc")],
            [InlineKeyboardButton("← Назад", callback_data="back_main")],
        ])
        await query.edit_message_text(TEXT_PRIVACY, parse_mode="HTML", reply_markup=kb)

    elif data == "password":
        context.user_data["mode"] = "password"
        await query.edit_message_text(
            TEXT_PASSWORD_PROMPT, parse_mode="HTML", reply_markup=kb_back_main()
        )

    elif data == "osint":
        await query.edit_message_text(
            TEXT_OSINT, parse_mode="HTML", reply_markup=kb_back_main()
        )


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = context.user_data.get("mode")
    text = update.message.text or ""

    if mode == "url":
        url = text.strip()
        if not url.startswith(("http://", "https://")):
            await update.message.reply_text(
                "Пришли ссылку начинающуюся с http:// или https://",
                reply_markup=kb_back_main()
            )
            return

        msg = await update.message.reply_text("Проверяю...")
        result = analyze_url_vt(url)

        if "error" in result:
            text_out = f"Ошибка: {result['error']}"
        elif "status" in result:
            text_out = result['message']
        else:
            m = result["malicious"]
            s = result["suspicious"]
            t = result["total"]

            if m >= 5:
                verdict = "🔴 Опасно — угрозы найдены"
            elif m >= 1 or s >= 3:
                verdict = "🟠 Подозрительно"
            elif s >= 1:
                verdict = "🟡 Осторожно"
            else:
                verdict = "🟢 Безопасно"

            text_out = (
                f"Результат анализа:\n\n"
                f"<code>{url[:60]}{'...' if len(url)>60 else ''}</code>\n\n"
                f"{verdict}\n\n"
                f"Сканеров: {t}\n"
                f"Вредоносных: {m}\n"
                f"Подозрительных: {s}\n"
                f"Безопасных: {result['harmless']}"
            )

        await msg.edit_text(text_out, parse_mode="HTML", reply_markup=kb_back_main())

    elif mode == "password":
        password = text
        strength = check_password_strength(password)
        pwned, count = check_hibp(password)

        bar = "█" * strength["score"] + "░" * (6 - strength["score"])
        tips_text = "\n".join(strength["tips"]) if strength["tips"] else "Всё норм"

        if pwned is None:
            pwned_text = "Не удалось проверить (нет интернета?)"
        elif pwned:
            pwned_text = f"⚠️ Найден в {count:,} утечках! Смени пароль."
        else:
            pwned_text = "✅ Не в утечках"

        result_text = (
            f"Сложность: {strength['level']}\n"
            f"[{bar}] {strength['score']}/6\n"
            f"Энтропия: ~{strength['entropy']} бит\n\n"
            f"Утечки: {pwned_text}\n\n"
            f"Советы:\n{tips_text}"
        )

        await update.message.reply_text(
            result_text, parse_mode="HTML", reply_markup=kb_back_main()
        )

    else:
        await update.message.reply_text(
            "Выбери действие из меню",
            reply_markup=kb_main()
        )


async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = context.user_data.get("mode")
    if mode != "file":
        await update.message.reply_text(
            "Сначала выбери «Проверить файл» в меню",
            reply_markup=kb_main()
        )
        return

    doc = update.message.document
    if not doc:
        await update.message.reply_text("Отправь файл через скрепку (не фото)")
        return

    if doc.file_size > 20 * 1024 * 1024:
        await update.message.reply_text("Файл больше 20 МБ")
        return

    msg = await update.message.reply_text("Скачиваю и проверяю...")

    try:
        file = await doc.get_file()
        file_bytes = await file.download_as_bytearray()

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()

        result = analyze_file_vt(sha256)

        if "error" in result:
            text_out = f"Ошибка VirusTotal: {result['error']}\n\nSHA256: <code>{sha256}</code>"
        elif result.get("not_found"):
            text_out = (
                f"Файл не в базе VirusTotal\n\n"
                f"SHA256: <code>{sha256}</code>\n"
                f"MD5: <code>{md5}</code>\n\n"
                f"Загрузи вручную на virustotal.com если нужна проверка"
            )
        else:
            m = result["malicious"]
            s = result["suspicious"]
            t = result["total"]

            if m >= 5:
                verdict = "🔴 Вредоносный"
            elif m >= 1 or s >= 3:
                verdict = "🟠 Подозрительный"
            elif s >= 1:
                verdict = "🟡 Осторожно"
            else:
                verdict = "🟢 Чистый"

            text_out = (
                f"Результат:\n\n"
                f"Имя: <code>{doc.file_name}</code>\n"
                f"Размер: {doc.file_size // 1024} КБ\n\n"
                f"{verdict}\n\n"
                f"Сканеров: {t}\n"
                f"Вредоносных: {m}\n"
                f"Подозрительных: {s}\n"
                f"Безопасных: {result['harmless']}"
            )

        await msg.edit_text(text_out, parse_mode="HTML", reply_markup=kb_back_main())

    except Exception as e:
        await msg.edit_text(f"Ошибка: {e}", reply_markup=kb_back_main())


# ─── REGISTER HANDLERS ───────────────────────────────────────────────────────
application.add_handler(CommandHandler("start", cmd_start))
application.add_handler(CallbackQueryHandler(button_handler))
application.add_handler(MessageHandler(filters.Document.ALL, file_handler))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

# ─── FLASK WEBHOOK ────────────────────────────────────────────────────────

@flask_app.route(f"/{BOT_TOKEN}", methods=["POST"])
def webhook():
    global loop
    
    data = request.get_json(force=True)
    update = Update.de_json(data, application.bot)
    
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    future = asyncio.run_coroutine_threadsafe(
        application.process_update(update),
        loop
    )
    
    try:
        future.result(timeout=30)
    except Exception as e:
        print(f"Error processing update: {e}")
    
    return "ok", 200

@flask_app.route("/")
def index():
    return "Bot is running", 200

@flask_app.route("/set_webhook")
def set_webhook():
    global loop
    
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    future = asyncio.run_coroutine_threadsafe(
        application.bot.set_webhook(f"{WEBHOOK_URL}/{BOT_TOKEN}"),
        loop
    )
    
    try:
        future.result(timeout=30)
        return f"Webhook: {WEBHOOK_URL}/{BOT_TOKEN}", 200
    except Exception as e:
        return f"Error: {str(e)}", 500

# ─── ENTRY POINT ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import threading
    
    def run_bot_loop():
        global loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(application.initialize())
    
    bot_thread = threading.Thread(target=run_bot_loop, daemon=True)
    bot_thread.start()
    
    port = int(os.environ.get("PORT", 5000))
    flask_app.run(host="0.0.0.0", port=port, debug=False)
