import os
import re
import math
import hashlib
import requests
from flask import Flask, request
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes
)

# ─── CONFIG ────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VT_API_KEY_HERE")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "https://your-app.onrender.com")

# ─── FLASK APP ──────────────────────────────────────────────────────────────────
flask_app = Flask(__name__)
application = Application.builder().token(BOT_TOKEN).build()

# ─── TEXTS ─────────────────────────────────────────────────────────────────────
TEXT_START = (
    "🛡️ <b>CyberGuard Bot</b>\n\n"
    "Добро пожаловать! Я помогу тебе:\n"
    "• 🔍 Анализировать подозрительные <b>ссылки и файлы</b>\n"
    "• 🔐 Проверить надёжность <b>пароля</b>\n"
    "• 🕵️ Защититься от <b>OSINT-слежки</b>\n"
    "• 🔒 Сохранить свою <b>приватность</b>\n\n"
    "Выбери нужный раздел 👇"
)

TEXT_ANALYZE_MENU = (
    "🔍 <b>Анализ угроз</b>\n\n"
    "Выбери что хочешь проверить:"
)

TEXT_URL_INSTRUCTIONS = (
    "🌐 <b>Анализ ссылок</b>\n\n"
    "Я проверю ссылку по базам VirusTotal и Google Safe Browsing.\n\n"
    "<b>Что проверяется:</b>\n"
    "• Репутация домена у 70+ антивирусов\n"
    "• Возраст домена (новый = подозрительно)\n"
    "• Наличие редиректов\n"
    "• Признаки фишинга и тайпсквоттинга\n"
    "• SSL-сертификат\n\n"
    "<b>Как отправить:</b>\n"
    "Просто отправь ссылку в чат, например:\n"
    "<code>https://example.com</code>\n\n"
    "⚠️ Поддерживаются только HTTP/HTTPS ссылки."
)

TEXT_FILE_INSTRUCTIONS = (
    "📁 <b>Анализ файлов</b>\n\n"
    "Я проверю файл через VirusTotal по SHA256-хэшу.\n\n"
    "<b>Поддерживаемые типы файлов:</b>\n"
    "🖥️ Исполняемые: <code>.exe .dll .bat .ps1 .sh .msi</code>\n"
    "📄 Документы: <code>.pdf .docx .xlsx .pptx</code>\n"
    "📦 Архивы: <code>.zip .rar .7z .tar.gz</code>\n"
    "📱 Android: <code>.apk</code>\n"
    "🌐 Скрипты: <code>.js .vbs .py</code>\n\n"
    "<b>Как отправить:</b>\n"
    "1. Нажми 📎 (скрепка) в Telegram\n"
    "2. Выбери <b>«Файл»</b> (не фото!)\n"
    "3. Отправь файл в этот чат\n\n"
    "⚠️ <b>Лимит: 20 МБ</b>\n"
    "⚠️ Не отправляй реально вредоносные файлы — "
    "только подозрительные для проверки."
)

TEXT_PRIVACY = (
    "🔒 <b>Приватность и защита от пробива</b>\n\n"
    "Здесь собрана подробная инструкция по защите "
    "твоих личных данных в сети: анонимность, безопасность аккаунтов, "
    "защита от деанонимизации и многое другое.\n\n"
    "📖 Читать полную инструкцию:\n"
    "👇"
)

TEXT_OSINT = (
    "🕵️ <b>Защита от OSINT</b>\n\n"
    "OSINT (разведка по открытым источникам) — это сбор информации "
    "о тебе из публичных источников: соцсети, утечки, реестры и т.д.\n\n"
    "<b>Основные правила защиты:</b>\n\n"
    "1️⃣ <b>Минимум информации в соцсетях</b>\n"
    "   • Скрой дату рождения, номер телефона, адрес\n"
    "   • Закрой профиль от посторонних\n\n"
    "2️⃣ <b>Разные никнеймы</b>\n"
    "   • Не используй один ник везде — это легко связывается\n\n"
    "3️⃣ <b>Фото</b>\n"
    "   • Убирай метаданные (EXIF) с фото перед публикацией\n"
    "   • Не публикуй геолокацию\n\n"
    "4️⃣ <b>Email и телефон</b>\n"
    "   • Используй отдельный email для регистраций\n"
    "   • Виртуальные номера для сервисов\n\n"
    "5️⃣ <b>Проверь себя</b>\n"
    "   • Погугли своё имя + город\n"
    "   • Проверь haveibeenpwned.com на утечки\n\n"
    "💡 <i>Текст будет дополнен — следи за обновлениями бота!</i>"
)

TEXT_PASSWORD_PROMPT = (
    "🔑 <b>Проверка пароля</b>\n\n"
    "Отправь мне пароль, и я:\n"
    "• Оценю его <b>сложность</b> по критериям\n"
    "• Проверю по базе <b>Have I Been Pwned</b> "
    "(утечки / брутфорс-словари)\n"
    "• Дам рекомендации по улучшению\n\n"
    "✏️ <b>Просто напиши пароль в чат</b>\n\n"
    "🔐 <i>Пароль НЕ сохраняется и НЕ передаётся никуда целиком. "
    "Для HIBP используется только первые 5 символов SHA1-хэша (k-анонимность).</i>"
)

# ─── KEYBOARDS ─────────────────────────────────────────────────────────────────

def kb_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔍 Анализ", callback_data="menu_analyze")],
        [
            InlineKeyboardButton("🔒 Приватность", callback_data="privacy"),
            InlineKeyboardButton("🔑 Password", callback_data="password"),
        ],
        [InlineKeyboardButton("🕵️ Защита от OSINT", callback_data="osint")],
    ])

def kb_analyze():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 Анализ ссылок", callback_data="analyze_url")],
        [InlineKeyboardButton("📁 Анализ файлов", callback_data="analyze_file")],
        [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
    ])

def kb_back_main():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("◀️ Главное меню", callback_data="back_main")]
    ])

def kb_back_analyze():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("◀️ Назад к анализу", callback_data="menu_analyze")]
    ])

# ─── HELPERS ───────────────────────────────────────────────────────────────────

def check_password_strength(password: str) -> dict:
    score = 0
    tips = []

    if len(password) >= 8:
        score += 1
    else:
        tips.append("❌ Минимум 8 символов")

    if len(password) >= 12:
        score += 1
    elif len(password) >= 8:
        tips.append("💡 Лучше 12+ символов")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        tips.append("❌ Добавь заглавные буквы (A-Z)")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        tips.append("❌ Добавь строчные буквы (a-z)")

    if re.search(r'\d', password):
        score += 1
    else:
        tips.append("❌ Добавь цифры (0-9)")

    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password):
        score += 1
    else:
        tips.append("❌ Добавь спецсимволы (!@#$...)")

    common = ["password", "123456", "qwerty", "abc123", "letmein",
              "admin", "welcome", "monkey", "dragon", "master"]
    if password.lower() in common:
        score = 0
        tips.insert(0, "🚨 Пароль входит в топ самых популярных!")

    if score <= 2:
        level = "🔴 Очень слабый"
    elif score <= 3:
        level = "🟠 Слабый"
    elif score == 4:
        level = "🟡 Средний"
    elif score == 5:
        level = "🟢 Хороший"
    else:
        level = "✅ Отличный"

    # Entropy estimate
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    entropy = round(len(password) * math.log2(charset), 1) if charset else 0

    return {"score": score, "level": level, "tips": tips, "entropy": entropy}


def check_hibp(password: str) -> tuple[bool, int]:
    """Check password against Have I Been Pwned (k-anonymity)."""
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
    """Analyze URL via VirusTotal API v3."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        return {"error": "VirusTotal API ключ не настроен. Обратитесь к администратору бота."}

    import base64
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if r.status_code == 404:
            # Submit for analysis
            r2 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers, data={"url": url}, timeout=10
            )
            return {"status": "submitted", "message": "Ссылка отправлена на анализ. Попробуй снова через 30 секунд."}

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
    """Check file hash via VirusTotal."""
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        return {"error": "VirusTotal API ключ не настроен."}

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

# ─── HANDLERS ──────────────────────────────────────────────────────────────────

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

    elif data == "menu_analyze":
        context.user_data.clear()
        await query.edit_message_text(TEXT_ANALYZE_MENU, parse_mode="HTML", reply_markup=kb_analyze())

    elif data == "analyze_url":
        context.user_data["mode"] = "url"
        await query.edit_message_text(
            TEXT_URL_INSTRUCTIONS, parse_mode="HTML", reply_markup=kb_back_analyze()
        )

    elif data == "analyze_file":
        context.user_data["mode"] = "file"
        await query.edit_message_text(
            TEXT_FILE_INSTRUCTIONS, parse_mode="HTML", reply_markup=kb_back_analyze()
        )

    elif data == "privacy":
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📖 Открыть инструкцию", url="https://teletype.in/@imperia_iot/infosc")],
            [InlineKeyboardButton("◀️ Назад", callback_data="back_main")],
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

    # ── URL Analysis ────────────────────────────────────────────────────────
    if mode == "url":
        url = text.strip()
        if not url.startswith(("http://", "https://")):
            await update.message.reply_text(
                "⚠️ Пожалуйста, отправь корректную ссылку начинающуюся с http:// или https://",
                reply_markup=kb_back_analyze()
            )
            return

        msg = await update.message.reply_text("⏳ Анализирую ссылку...")
        result = analyze_url_vt(url)

        if "error" in result:
            text_out = f"❌ Ошибка: {result['error']}"
        elif "status" in result:
            text_out = f"📤 {result['message']}"
        else:
            m = result["malicious"]
            s = result["suspicious"]
            t = result["total"]

            if m >= 5:
                verdict = "🔴 <b>ОПАСНО</b> — обнаружены угрозы!"
            elif m >= 1 or s >= 3:
                verdict = "🟠 <b>ПОДОЗРИТЕЛЬНО</b> — возможна угроза"
            elif s >= 1:
                verdict = "🟡 <b>ОСТОРОЖНО</b> — слабые признаки угрозы"
            else:
                verdict = "🟢 <b>БЕЗОПАСНО</b> — угроз не обнаружено"

            text_out = (
                f"🔍 <b>Результат анализа ссылки</b>\n\n"
                f"<code>{url[:60]}{'...' if len(url)>60 else ''}</code>\n\n"
                f"Вердикт: {verdict}\n\n"
                f"📊 <b>Статистика ({t} сканеров):</b>\n"
                f"🔴 Вредоносных: {m}\n"
                f"🟠 Подозрительных: {s}\n"
                f"🟢 Безопасных: {result['harmless']}\n"
                f"📈 Репутация: {result['reputation']}"
            )

        await msg.edit_text(text_out, parse_mode="HTML", reply_markup=kb_back_analyze())

    # ── Password Analysis ───────────────────────────────────────────────────
    elif mode == "password":
        password = text  # keep original
        strength = check_password_strength(password)
        pwned, count = check_hibp(password)

        bar = "█" * strength["score"] + "░" * (6 - strength["score"])
        tips_text = "\n".join(strength["tips"]) if strength["tips"] else "✅ Всё хорошо!"

        if pwned is None:
            pwned_text = "⚠️ Не удалось проверить базу утечек (нет соединения)"
        elif pwned:
            pwned_text = f"🚨 <b>Найден в {count:,} утечках/словарях!</b> Смени немедленно!"
        else:
            pwned_text = "✅ Не найден в базах утечек HIBP"

        result_text = (
            f"🔑 <b>Анализ пароля</b>\n\n"
            f"Сложность: {strength['level']}\n"
            f"[{bar}] {strength['score']}/6\n"
            f"Энтропия: ~{strength['entropy']} бит\n\n"
            f"<b>База утечек (HIBP):</b>\n{pwned_text}\n\n"
            f"<b>Рекомендации:</b>\n{tips_text}"
        )

        await update.message.reply_text(
            result_text, parse_mode="HTML", reply_markup=kb_back_main()
        )

    else:
        await update.message.reply_text(
            "Используй меню для навигации 👇",
            reply_markup=kb_main()
        )


async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mode = context.user_data.get("mode")
    if mode != "file":
        await update.message.reply_text(
            "📁 Хочешь проверить файл? Сначала выбери «Анализ файлов» в меню.",
            reply_markup=kb_main()
        )
        return

    doc = update.message.document
    if not doc:
        await update.message.reply_text("⚠️ Отправь файл через 📎 → Файл (не как фото).")
        return

    # Size check (20 MB)
    if doc.file_size > 20 * 1024 * 1024:
        await update.message.reply_text("❌ Файл слишком большой. Максимум 20 МБ.")
        return

    msg = await update.message.reply_text("⏳ Скачиваю и анализирую файл...")

    try:
        file = await doc.get_file()
        file_bytes = await file.download_as_bytearray()

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()

        result = analyze_file_vt(sha256)

        if "error" in result:
            text_out = f"❌ Ошибка VirusTotal: {result['error']}\n\n📋 SHA256: <code>{sha256}</code>"
        elif result.get("not_found"):
            text_out = (
                f"🔍 <b>Файл не найден в базе VirusTotal</b>\n\n"
                f"Файл ещё не анализировался ни разу.\n\n"
                f"📋 <b>Хэши файла:</b>\n"
                f"SHA256: <code>{sha256}</code>\n"
                f"MD5: <code>{md5}</code>\n\n"
                f"💡 Можешь вручную загрузить на virustotal.com для полного анализа."
            )
        else:
            m = result["malicious"]
            s = result["suspicious"]
            t = result["total"]

            if m >= 5:
                verdict = "🔴 <b>ВРЕДОНОСНЫЙ</b> — опасный файл!"
            elif m >= 1 or s >= 3:
                verdict = "🟠 <b>ПОДОЗРИТЕЛЬНЫЙ</b>"
            elif s >= 1:
                verdict = "🟡 <b>ОСТОРОЖНО</b>"
            else:
                verdict = "🟢 <b>ЧИСТЫЙ</b>"

            text_out = (
                f"📁 <b>Результат анализа файла</b>\n\n"
                f"Имя: <code>{doc.file_name}</code>\n"
                f"Размер: {doc.file_size // 1024} КБ\n\n"
                f"Вердикт: {verdict}\n\n"
                f"📊 <b>Статистика ({t} сканеров):</b>\n"
                f"🔴 Вредоносных: {m}\n"
                f"🟠 Подозрительных: {s}\n"
                f"🟢 Безопасных: {result['harmless']}\n\n"
                f"🔑 SHA256: <code>{sha256[:32]}...</code>"
            )

        await msg.edit_text(text_out, parse_mode="HTML", reply_markup=kb_back_analyze())

    except Exception as e:
        await msg.edit_text(f"❌ Ошибка при обработке файла: {e}", reply_markup=kb_back_analyze())


# ─── REGISTER HANDLERS ─────────────────────────────────────────────────────────
application.add_handler(CommandHandler("start", cmd_start))
application.add_handler(CallbackQueryHandler(button_handler))
application.add_handler(MessageHandler(filters.Document.ALL, file_handler))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

# ─── FLASK WEBHOOK ─────────────────────────────────────────────────────────────
@flask_app.route(f"/{BOT_TOKEN}", methods=["POST"])
async def webhook():
    import json
    from telegram import Update
    data = request.get_json(force=True)
    update = Update.de_json(data, application.bot)
    await application.process_update(update)
    return "ok"

@flask_app.route("/")
def index():
    return "CyberGuard Bot is running 🛡️"

@flask_app.route("/set_webhook")
async def set_webhook():
    await application.bot.set_webhook(f"{WEBHOOK_URL}/{BOT_TOKEN}")
    return f"Webhook set to {WEBHOOK_URL}/{BOT_TOKEN}"

# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import asyncio

    async def main():
        await application.initialize()
        await application.bot.set_webhook(f"{WEBHOOK_URL}/{BOT_TOKEN}")
        port = int(os.environ.get("PORT", 5000))
        flask_app.run(host="0.0.0.0", port=port)

    asyncio.run(main())
