# Recovered from an obfuscated marshal/XOR loader (Python 3.11).
# Static reconstruction: XOR decrypt + marshal.loads + disassembly, no payload exec.

import os
import re
import time
import logging
import random
import shlex
import secrets
import pytz
import shutil
import asyncio
import traceback
import httpx
import json
from typing import Tuple, Dict, Any, Optional
from os.path import join
from datetime import datetime, timedelta
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
from pyrogram import Client, filters, enums
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from pyrogram.errors import PeerIdInvalid, MessageNotModified
import subprocess
from urllib.parse import urlparse
import sys
import config
import aiofiles
import hachoir

OUTPUT_DIR = "pyrogram_recordings"
os.makedirs(OUTPUT_DIR, exist_ok=True)
FLOG_DIR = "flogs"
MAX_FILE_SIZE = 2040109465
pending_states = {}
job_queue = asyncio.Queue()
running_jobs = {}
LOG_FOLDER = "logs"
os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(FLOG_DIR, exist_ok=True)
LOG_FILENAME = datetime.now().strftime(f"{LOG_FOLDER}/bot_%Y-%m-%d_%H-%M-%S.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILENAME, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
LOG = logging.getLogger(__name__)


def escape_html(text):
    """Escapes HTML special characters in a string to prevent XSS or parsing errors."""
    if not isinstance(text, str):
        text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


try:
    client_mongo = MongoClient(config.MONGO_URI)
    db = client_mongo.get_database("DoraToonzDB")
    premium_users_collection = db["premium_users"]
    verification_tokens_collection = db["verification_tokens"]
    admin_users_collection = db["admins"]
    LOG.info("Connected to MongoDB successfully!")
except PyMongoError as e:
    LOG.critical(f"Failed to connect to MongoDB: {e}")
    raise SystemExit(1)

dtbot = Client(
    "recorder",
    bot_token=config.BOT_TOKEN,
    api_id=config.API_ID,
    api_hash=config.API_HASH,
)
user_status: Dict[int, list] = {}
user_tasks: Dict[int, int] = {}
STATUS_PAGE_SIZE = 5
CHANNELS_PER_PAGE = 10
GLOBAL_MAX_PARALLEL_TASKS = 4
global_search_results: Dict[int, Dict[str, Any]] = {}
user_waiting_for_title: Dict[int, Dict[str, Any]] = {}


def is_owner(user_id):
    return user_id == config.OWNER_ID


def is_admin(user_id):
    if admin_users_collection.find_one({"_id": user_id}):
        return True
    return is_owner(user_id)


def is_premium_user(user_id):
    if is_admin(user_id):
        return True
    record = premium_users_collection.find_one({"_id": user_id})
    if record and record.get("is_premium") and record.get("expires_at", 0) > int(time.time()):
        return True
    return False


def is_user_verified_integrated(user_id):
    """Check if user is verified and verification hasn't expired."""
    now = int(time.time())
    record = verification_tokens_collection.find_one({"_id": user_id})
    if record and record.get("verified") and record.get("expires_at", 0) > now:
        return True
    return False


async def send_verification_message_integrated(bot, message):
    user_id = message.from_user.id
    username = message.from_user.username or message.from_user.first_name
    now = int(time.time())
    existing = verification_tokens_collection.find_one({"_id": user_id})
    if existing:
        expires_at = existing.get("expires_at", 0)
        if existing.get("verified") and now < expires_at:
            remaining = expires_at - now
            await message.reply(
                f"✅ You're already verified! Keep rocking!🤘\n⏳ Remaining time: <code>{remaining // 3600}h {(remaining % 3600) // 60}m</code>",
                parse_mode=enums.ParseMode.HTML,
                quote=True,
            )
            return
    token = secrets.token_urlsafe(12)
    temp_expires_at = now + config.VERIFICATION_EXPIRY_SECONDS
    verification_tokens_collection.update_one(
        {"_id": user_id},
        {
            "$set": {
                "token": token,
                "username": username,
                "verified": False,
                "expires_at": temp_expires_at,
            }
        },
        upsert=True,
    )
    bot_username = await bot.get_me().username
    verify_url = f"https://telegram.me/{bot_username}?start=verify_{token}"
    shortlink = verify_url
    if config.ENABLE_SHORTLINK and config.SHORTLINK_URL and config.SHORTLINK_API:
        api_url = f"{config.SHORTLINK_URL}/api?api={config.SHORTLINK_API}&url={verify_url}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(api_url)
                data = resp.json()
                if data.get("status") == "success":
                    shortlink = data.get("shortenedUrl")
                    LOG.info(f"Generated shortlink for verification: {shortlink}")
                else:
                    LOG.warning(
                        f"Shortlink API returned error: {data.get('message', 'Unknown error')}"
                    )
        except Exception as e:
            LOG.error(f"Error calling shortlink API: {e}")
    markup = InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔗 Verify Here", url=shortlink)]]
    )
    await message.reply(
        f"🔐 <b>Verification Required!</b> 🚨<br><br>\nClick the button below to verify and unlock recording for <code>{config.VERIFICATION_EXPIRY_SECONDS // 3600} hours</code>.<br>\nAfter verification, you can use the <code>/rec</code> command! ✨",
        reply_markup=markup,
        parse_mode=enums.ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def complete_verification_integrated(bot, user_id, token):
    """Mark user as verified if token matches and is not expired."""
    now = int(time.time())
    record = verification_tokens_collection.find_one({"_id": user_id})
    token_value_from_deeplink = token.replace("verify_", "")
    if (
        record
        and record.get("token") == token_value_from_deeplink
        and record.get("expires_at", 0) > now
    ):
        new_expires_at = now + config.VERIFICATION_EXPIRY_SECONDS
        verification_tokens_collection.update_one(
            {"_id": user_id},
            {"$set": {"verified": True, "expires_at": new_expires_at}},
        )
        username = record.get("username", "User")
        try:
            await bot.send_message(
                config.WORKING_GROUP,
                f"✅ <b>{escape_html(username)}</b> has successfully verified and can now access recording features for <code>{config.VERIFICATION_EXPIRY_SECONDS // 3600} hours</code>. Welcome aboard! 🚀",
                parse_mode=enums.ParseMode.HTML,
            )
        except Exception as e:
            LOG.warning(
                f"Failed to send verification notification to working group: {e}"
            )
        return True
    return False


def get_user_tier_details(user_id):
    """Determines user's tier and associated limits."""
    tier_details = {
        "is_owner": is_owner(user_id),
        "is_admin": is_admin(user_id),
        "is_premium": is_premium_user(user_id),
        "is_verified": is_user_verified_integrated(user_id),
        "max_duration_sec": 0,
        "max_user_tasks": 0,
        "tier_name": "Guest",
    }
    if tier_details["is_owner"]:
        tier_details["tier_name"] = "Owner"
        tier_details["max_duration_sec"] = float("inf")
        tier_details["max_user_tasks"] = float("inf")
    elif tier_details["is_admin"]:
        tier_details["tier_name"] = "Admin"
        tier_details["max_duration_sec"] = float("inf")
        tier_details["max_user_tasks"] = config.PREMIUM_PARALLEL_TASKS
    elif tier_details["is_premium"]:
        tier_details["tier_name"] = "Premium"
        tier_details["max_duration_sec"] = config.PREMIUM_MAX_DURATION_SEC
        tier_details["max_user_tasks"] = config.PREMIUM_PARALLEL_TASKS
    elif config.ENABLE_SHORTLINK and tier_details["is_verified"]:
        tier_details["tier_name"] = "Verified"
        tier_details["max_duration_sec"] = config.VERIFIED_MAX_DURATION_SEC
        tier_details["max_user_tasks"] = config.VERIFIED_PARALLEL_TASKS
    elif not config.ENABLE_SHORTLINK:
        tier_details["tier_name"] = "Default User"
        tier_details["max_duration_sec"] = 900
        tier_details["max_user_tasks"] = 1
    return tier_details


def owner_only(func):
    async def wrapper(client, message):
        if not is_owner(message.from_user.id):
            await message.reply_text(
                "🚫 <b>Access Denied:</b> This command is for the bot owner only. How did you even find this? 🤔",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        await func(client, message)

    return wrapper


def admin_only(func):
    async def wrapper(client, message):
        if not is_admin(message.from_user.id):
            await message.reply_text(
                "🚫 <b>Access Denied:</b> This command is for administrators only. Shoo! 🤫",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        await func(client, message)

    return wrapper


def requester_or_admin(func):
    """
    Decorator to ensure only the original requester OR an admin can use a callback button.
    """

    async def wrapper(client, callback_query):
        try:
            requester_id = int(callback_query.data.split("_")[1])
        except (IndexError, ValueError):
            LOG.error(
                f"Callback data '{callback_query.data}' has an invalid format for restriction."
            )
            await callback_query.answer(
                "⚠️ This button is broken or outdated.", show_alert=True
            )
            return
        if callback_query.from_user.id == requester_id or is_admin(
            callback_query.from_user.id
        ):
            await func(client, callback_query)
            return
        await callback_query.answer("🚫 This action is not for you!", show_alert=True)

    return wrapper


def admin_or_premium_only(func):
    async def wrapper(client, message):
        user_id = message.from_user.id
        if not is_admin(user_id) and not is_premium_user(user_id):
            await message.reply_text(
                "⛔ <b>Access Denied:</b> This feature is for premium users and administrators only. Upgrade your perks! ✨",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        await func(client, message)

    return wrapper


def admin_only_cb(func):
    async def wrapper(client, callback_query):
        if not is_admin(callback_query.from_user.id):
            await callback_query.answer(
                "⛔ Access Denied: This action is for administrators only. Move along! 👋",
                show_alert=True,
            )
            return
        await func(client, callback_query)

    return wrapper


def user_is_requester(func):
    """
    Decorator to ensure only the user who initiated an action can interact with its callback buttons.
    This is the primary security measure against button hijacking.
    """

    async def wrapper(client, callback_query):
        try:
            requester_id = int(callback_query.data.split("_")[1])
        except (IndexError, ValueError):
            LOG.error(
                f"Callback data '{callback_query.data}' has an invalid format for user restriction."
            )
            await callback_query.answer(
                "⚠️ This button seems to be broken or outdated. Please try the original command again.",
                show_alert=True,
            )
            return
        if callback_query.from_user.id != requester_id:
            await callback_query.answer("🚫 This menu is not for you!", show_alert=True)
            return
        await func(client, callback_query)

    return wrapper


async def unauthorized_access(message):
    """Replies to a user with an unauthorized access message."""
    await message.reply_text(
        f"❌ <b>You cannot access this bot feature from here.</b><br>\nAccess is allowed only in our official group: <a href='{escape_html(config.GROUP_LINK)}'>Recording Group</a> 👥",
        parse_mode=enums.ParseMode.HTML,
    )


def sanitize_filename(name):
    """Sanitizes a string to be a valid filename."""
    return re.sub(r'[\\/:"*?<>|]+', "", name).strip()


def load_m3u8_channels():
    """Loads all M3U8 channel data from JSON files in the configured directory."""
    channels_data = {}
    if not os.path.exists(config.M3U8_FILES_DIRECTORY):
        os.makedirs(config.M3U8_FILES_DIRECTORY, exist_ok=True)
        return channels_data
    for filename in os.listdir(config.M3U8_FILES_DIRECTORY):
        if filename.endswith(".json"):
            filepath = os.path.join(config.M3U8_FILES_DIRECTORY, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    file_content = json.load(f)
                list_name_from_file = filename[:-5]
                if isinstance(file_content, dict):
                    channels_data[list_name_from_file] = file_content
                else:
                    LOG.warning(
                        f"JSON file {filename} root is not a dictionary. Skipping. 🤷‍♀️"
                    )
            except json.JSONDecodeError as e:
                LOG.error(f"Error decoding JSON from {filename}: {e} 😵")
            except Exception as e:
                LOG.error(f"Error loading {filename}: {e} 😬")
    return channels_data


def get_channel_details_from_all_lists(channel_name_query, list_identifier=None):
    """
    Searches for a channel across all loaded M3U8 lists.
    If list_identifier is provided (e.g., ".L1"), it searches only in that specific list.
    """
    channels_data = load_m3u8_channels()
    normalized_query = channel_name_query.lower()
    target_list_name = None
    if list_identifier:
        try:
            list_index = int(list_identifier[2:]) - 1
            sorted_list_names = sorted(channels_data.keys())
            if 0 <= list_index < len(sorted_list_names):
                target_list_name = sorted_list_names[list_index]
            else:
                LOG.warning(
                    f"Invalid list identifier: {list_identifier}. Index out of bounds. 🤯"
                )
                return None
        except ValueError:
            LOG.warning(f"Invalid list identifier format: {list_identifier} 🚫")
            return None
    search_lists = (
        {target_list_name: channels_data[target_list_name]}
        if target_list_name
        else channels_data
    )
    for list_name, channels_in_list in search_lists.items():
        for key, details in channels_in_list.items():
            if (
                normalized_query == details.get("name", "").lower()
                or normalized_query == key.lower()
            ):
                return {**details, "found_in_list": list_name}
    return None


async def build_tasks_output(tasks_list, current_page_display, total_pages):
    """Helper to build formatted task list output for /tasks and /mytasks."""
    if not tasks_list:
        return "ℹ️ <b>No active recording tasks found.</b>"
    output_lines = []
    for st in tasks_list:
        progress_msg_link = ""
        if st.get("progress_message_id") and st.get("chat_id"):
            chat_id_for_link = str(st["chat_id"])
            if chat_id_for_link.startswith("-100"):
                chat_id_for_link = chat_id_for_link[4:]
            progress_msg_link = f" <a href='https://t.me/c/{chat_id_for_link}/{st['progress_message_id']}'>🔗 Progress</a>"
        username_display = "Anonymous"
        if st.get("user_id"):
            try:
                user_info = await dtbot.get_users(st["user_id"])
                username_display = (
                    user_info.first_name or f"ID: {st['user_id']}"
                )
            except Exception:
                username_display = f"ID: {st['user_id']}"
        output_lines.append(
            f"👤 <b>User:</b> {escape_html(username_display)}"
            f"\n🔹 <b>Task ID:</b> <code>{st['id']}</code>{progress_msg_link}"
            f"\n🔹 <b>Filename:</b> <code>{escape_html(st['filename'])}</code>"
            f"\n🔹 <b>Duration:</b> <code>{escape_html(st['target'])}</code>"
            f"\n🔹 <b>Status:</b> <i>{escape_html(st.get('status', '...'))}</i>"
        )
    joined_lines = "\n----------------------------------\n".join(output_lines)
    header = f"📊 <b>Active Recording Tasks — Page {current_page_display}/{total_pages}</b>\n\n"
    if total_pages <= 1:
        header = "📊 <b>Active Recording Tasks</b>\n\n"
    text = header + joined_lines
    return text


def parse_duration(duration_str):
    """Converts HH:MM:SS or seconds string to total seconds."""
    if ":" in duration_str:
        parts = list(map(int, duration_str.split(":")))
        seconds = 0
        if len(parts) == 3:
            seconds = parts[0] * 3600 + parts[1] * 60 + parts[2]
        elif len(parts) == 2:
            seconds = parts[0] * 60 + parts[1]
        return seconds
    return int(duration_str)


def format_duration_hhmmss(seconds):
    """Formats a duration in seconds into HH:MM:SS string."""
    if seconds < 0:
        return "00:00:00"
    (h, remainder) = divmod(seconds, 3600)
    (m, s) = divmod(remainder, 60)
    return f"{int(h):02}:{int(m):02}:{int(s):02}"


def get_duration(file_path):
    """
    Gets video duration using ffprobe, with hachoir as a fallback.
    Also includes better error logging.
    """
    if os.path.exists(file_path):
        try:
            proc = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "default=noprint_wrappers=1:nokey=1",
                    file_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True,
            )
            return int(float(proc.stdout.strip()))
        except Exception as e:
            LOG.error(f"FFPROBE FAILED to get duration for {file_path}: {e}")
        try:
            parser = createParser(file_path)
            if not parser:
                LOG.error(f"Hachoir could not parse file: {file_path}")
                return 0
            metadata = extractMetadata(parser)
            duration = metadata.get("duration") if metadata else None
            if duration:
                return duration.seconds
        except Exception as e:
            LOG.error(f"HACHOIR FAILED to get duration for {file_path}: {e}")
        return 0
    LOG.error(f"File not found when trying to get duration: {file_path}")
    return 0


async def generate_thumbnail(video_path):
    """Generates a thumbnail for the video asynchronously."""
    thumb_path = f"{video_path}.jpg"
    loop = asyncio.get_running_loop()

    def _blocking_thumbnail_generation():
        try:
            duration_secs = get_duration(video_path) or 1
            ss_time = "00:00:05" if duration_secs > 5 else "00:00:01"
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-ss",
                    ss_time,
                    "-i",
                    video_path,
                    "-frames:v",
                    "1",
                    "-q:v",
                    "2",
                    thumb_path,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            if os.path.exists(thumb_path):
                from PIL import Image

                Image.open(thumb_path).convert("RGB").save(thumb_path, "JPEG")
                return thumb_path
        except Exception as e:
            LOG.error(f"Thumbnail generation failed for {video_path}: {e}")
        return None

    return await loop.run_in_executor(None, _blocking_thumbnail_generation)


async def split_video_by_size(input_file, max_size, output_dir):
    """Splits a video into parts asynchronously if it exceeds the max size."""
    loop = asyncio.get_running_loop()

    def _blocking_video_split():
        try:
            total_duration = get_duration(input_file)
            if not total_duration:
                return [input_file]
            total_size = os.path.getsize(input_file)
            if total_size <= max_size:
                return [input_file]
            num_parts = int(total_size / max_size) + 1
            part_duration = total_duration // num_parts
            (base_name, ext) = os.path.splitext(os.path.basename(input_file))
            split_files = []
            start_time = 0
            for i in range(num_parts):
                output_file = os.path.join(
                    output_dir, f"{base_name}_part{i + 1}{ext}"
                )
                cmd = ["ffmpeg", "-y", "-ss", str(start_time), "-i", input_file]
                if i < num_parts - 1:
                    cmd.extend(["-t", str(part_duration)])
                cmd.extend(["-c", "copy", output_file])
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                split_files.append(output_file)
                start_time += part_duration
            os.remove(input_file)
            return split_files
        except Exception as e:
            LOG.error(f"Error during video splitting: {e}")
            return [input_file]

    return await loop.run_in_executor(None, _blocking_video_split)


async def upload_single_file(
    bot,
    chat_id,
    file_path,
    caption,
    thumb_path=None,
    msg=None,
    original_message_id=None,
    job_id=None,
):
    """Uploads a single file with a progress bar."""
    start_time = time.time()
    last_edit_time = 0
    file_duration = get_duration(file_path) or 0

    async def progress(current, total, job_id_arg):
        nonlocal last_edit_time
        now = time.time()
        if now - last_edit_time < config.PROGRESS_UPDATE_INTERVAL:
            return
        percentage = current / total * 100
        speed = current / (now - start_time)
        eta = (total - current) / speed if speed > 0 else 0
        progress_bar = f"[{'⬢' * int(percentage / 10)}{'⬡' * (10 - int(percentage / 10))}]"
        text = (
            f"**🚀 Uploading...**\n`{progress_bar} {percentage:.2f}%`\n"
            f"**Size:** `{current / 1048576:.2f}MB / {total / 1048576:.2f}MB`\n"
            f"**Speed:** `{speed / 1048576:.2f} MB/s`\n"
            f"**ETA:** `{timedelta(seconds=int(eta))}`**Task ID:** `{job_id_arg}`\n\n"
        )
        try:
            await msg.edit_text(text)
            last_edit_time = now
        except Exception:
            return

    await bot.send_video(
        chat_id,
        file_path,
        caption=caption,
        thumb=thumb_path,
        duration=file_duration,
        progress=progress,
        progress_args=(job_id,),
        reply_to_message_id=original_message_id,
    )


async def upload_file_with_progress(
    bot,
    chat_id,
    file_path,
    caption,
    thumb_path=None,
    msg=None,
    original_message_id=None,
    job_id=None,
):
    """Handles splitting and uploading of a file."""
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            await msg.edit_text("🔄 File is too large, splitting into parts...")
            split_files = await split_video_by_size(
                file_path, MAX_FILE_SIZE, OUTPUT_DIR
            )
            is_first_part = True
            for (i, part_file) in enumerate(split_files):
                part_caption = f"**Part {i + 1}/{len(split_files)}**\n\n{caption}"
                part_thumb = await generate_thumbnail(part_file)
                part_msg = await bot.send_message(
                    chat_id, f"🚀 Uploading Part {i + 1}..."
                )
                await upload_single_file(
                    bot,
                    chat_id,
                    part_file,
                    part_caption,
                    part_thumb,
                    part_msg,
                    original_message_id if is_first_part else None,
                    job_id,
                )
                is_first_part = False
                await part_msg.delete()
                if os.path.exists(part_file):
                    os.remove(part_file)
                if part_thumb and os.path.exists(part_thumb):
                    os.remove(part_thumb)
        else:
            await upload_single_file(
                bot,
                chat_id,
                file_path,
                caption,
                thumb_path,
                msg,
                original_message_id,
                job_id,
            )
        if os.path.exists(file_path):
            os.remove(file_path)
        if thumb_path and os.path.exists(thumb_path):
            os.remove(thumb_path)
        await msg.delete()
    except PeerIdInvalid:
        error_text = "❌ Upload failed: I can't post in the target chat. I might have been kicked or the user blocked me."
        LOG.error(f"PeerIdInvalid for chat_id {chat_id}. Could not deliver file.")
        if msg:
            await msg.edit_text(error_text)
    except Exception as e:
        error_text = f"❌ Upload failed: {e}"
        LOG.error(error_text, exc_info=True)
        if msg:
            await msg.edit_text(error_text)


async def execute_ffmpeg_recording(
    chat_id,
    job_id,
    user_id,
    m3u8_url,
    duration,
    output_path,
    video_track,
    audio_maps,
    progress_msg,
    use_header=False,
):
    """Executes the FFmpeg recording process, conditionally adding headers."""
    try:
        log_file_path = os.path.join(FLOG_DIR, f"{job_id}.txt")
        cmd = ["ffmpeg", "-y"]
        if use_header:
            parsed_url = urlparse(m3u8_url)
            referer = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            headers_str = (
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 "
                "Safari/537.36\r\nReferer: " + referer + "\r\n"
            )
            cmd.extend(["-headers", headers_str])
        cmd.extend(["-i", m3u8_url])
        cmd.extend(["-map", f"0:{video_track['index']}" if video_track else "-vn"])
        cmd.extend(["-c:v", "copy" if video_track else None])
        if audio_maps:
            for audio_idx in audio_maps:
                cmd.extend(["-map", f"0:{audio_idx}", "-c:a", "copy"])
        else:
            cmd.append("-an")
        cmd.extend(["-map", "0:s?", "-c:s", "copy"])
        cmd.extend(["-t", str(duration), output_path])
        cmd = [c for c in cmd if c is not None]
        LOG.info(
            f"FFmpeg Command for job {job_id}: {' '.join(shlex.quote(c) for c in cmd)}"
        )
        proc = await asyncio.create_subprocess_exec(
            *cmd, stderr=asyncio.subprocess.PIPE
        )
        running_jobs[job_id] = proc
        time_regex = re.compile(r"time=(\d{2}):(\d{2}):(\d{2})\.\d{2}")
        last_update = 0
        async with aiofiles.open(log_file_path, "w", encoding="utf-8") as log_file:
            while True:
                if (
                    pending_states.get(chat_id, {})
                    .get(job_id, {})
                    .get("cancelled")
                ):
                    proc.terminate()
                    await proc.wait()
                    LOG.info(f"Terminated FFmpeg process for cancelled job {job_id}.")
                    await log_file.write("\n\n--- TASK CANCELLED BY USER ---\n")
                    break
                try:
                    line_bytes = await asyncio.wait_for(
                        proc.stderr.readline(), timeout=20
                    )
                except asyncio.TimeoutError:
                    LOG.warning(
                        f"FFmpeg for job {job_id} produced no output for 20s. Still running..."
                    )
                    await log_file.write(
                        "\n--- No output from FFmpeg for 20 seconds ---\n"
                    )
                    continue
                if not line_bytes:
                    break
                line_str = line_bytes.decode("utf-8", "ignore")
                await log_file.write(line_str)
                if time.time() - last_update > config.PROGRESS_UPDATE_INTERVAL:
                    match = time_regex.search(line_str)
                    if match:
                        (h, m, s) = match.groups()
                        elapsed = (
                            int(h) * 3600
                            + int(m) * 60
                            + int(s.split(".")[0])
                        )
                        percentage = elapsed / duration * 100
                        progress_bar = f"[{'⬢' * int(percentage / 10)}{'⬡' * (10 - int(percentage / 10))}]"
                        text = (
                            f"**🎬 Recording in progress...**\n`{progress_bar} {percentage:.1f}%`\n"
                            f"**Time:** `{timedelta(seconds=elapsed)}` / `{timedelta(seconds=duration)}`\n"
                            f"**Task ID:** `{job_id}`\n\n"
                        )
                        try:
                            await progress_msg.edit_text(
                                text,
                                reply_markup=InlineKeyboardMarkup(
                                    [
                                        [
                                            InlineKeyboardButton(
                                                "❌ Cancel",
                                                callback_data=f"cancel_{user_id}_{job_id}",
                                            )
                                        ]
                                    ]
                                ),
                            )
                            last_update = time.time()
                        except Exception:
                            pass
        await proc.wait()
        del running_jobs[job_id]
        if (
            pending_states.get(chat_id, {})
            .get(job_id, {})
            .get("cancelled")
        ):
            if os.path.exists(output_path):
                os.remove(output_path)
            return False
        return (
            proc.returncode == 0
            and os.path.exists(output_path)
            and os.path.getsize(output_path) > 1024
        )
    except Exception as e:
        LOG.error(f"FFmpeg execution error for job {job_id}: {e}", exc_info=True)
        if job_id in running_jobs:
            del running_jobs[job_id]
        return False


async def worker():
    """The main worker task that processes jobs from the queue."""
    while True:
        job = await job_queue.get()
        (chat_id, job_id) = (job["chat_id"], job["job_id"])
        try:
            progress_msg = await dtbot.get_messages(chat_id, job["msg_id"])
            user_id = pending_states.get(chat_id, {}).get(job_id, {}).get("user_id")
            if pending_states.get(chat_id, {}).get(job_id):
                pending_states[chat_id][job_id]["status"] = "Running 🏃‍♂️"
            use_header = job.get("use_header", False)
            success = await execute_ffmpeg_recording(
                chat_id,
                job_id,
                user_id,
                job["url"],
                job["duration"],
                job["filename"],
                job["video"],
                job["audios"],
                progress_msg,
                use_header,
            )
            if (
                pending_states.get(chat_id, {})
                .get(job_id, {})
                .get("cancelled")
            ):
                await progress_msg.edit_text("❌ Recording cancelled by user.")
            elif success:
                if pending_states.get(chat_id, {}).get(job_id):
                    pending_states[chat_id][job_id]["status"] = "Uploading 🚀"
                await progress_msg.edit_text(
                    "✅ Recording complete! Now uploading..."
                )
                thumb = await generate_thumbnail(job["filename"])
                final_duration = get_duration(job["filename"]) or 0
                caption = (
                    f"**📺 Recording Complete...**\n\n"
                    f"**📁 File Name:** `{os.path.basename(job['filename'])}`\n"
                    f"**⏱️ Duration:** `{format_duration_hhmmss(final_duration)}`\n\n"
                    f"**Task ID:** `{job_id}`\n\n"
                    f"Bot Developer: @Dora_Toonz @Shan_0103"
                )
                await upload_file_with_progress(
                    dtbot,
                    chat_id,
                    job["filename"],
                    caption,
                    thumb,
                    progress_msg,
                    job.get("original_message_id"),
                    job_id,
                )
            else:
                if pending_states.get(chat_id, {}).get(job_id):
                    pending_states[chat_id][job_id]["status"] = "Failed ❌"
                await progress_msg.edit_text(
                    "❌ Recording failed. The stream might be down or an FFmpeg error occurred."
                )
        except Exception as e:
            LOG.error(f"Worker error for job {job_id}: {e}", exc_info=True)
            if "progress_msg" in locals():
                await progress_msg.edit_text(
                    f"❌ An internal error occurred for job `{job_id[:8]}`."
                )
            if pending_states.get(chat_id, {}).get(job_id):
                pending_states[chat_id][job_id]["status"] = "Failed ❌"
        finally:
            await asyncio.sleep(10)
            if chat_id in pending_states and job_id in pending_states[chat_id]:
                job_dir = os.path.dirname(
                    pending_states[chat_id][job_id]["filename"]
                )
                if os.path.exists(job_dir):
                    shutil.rmtree(job_dir, ignore_errors=True)
                del pending_states[chat_id][job_id]
            job_queue.task_done()


@dtbot.on_callback_query(filters.regex("^audall_"))
async def callback_audio_select_all(bot, query):
    """Handles the 'Select All' audio button press, with correct toggle logic."""
    (_, user_id_str, job_id) = query.data.split("_")
    chat_id = query.message.chat.id
    sel = pending_states.get(chat_id, {}).get(job_id)
    if not sel:
        await query.answer("This recording session has expired!", show_alert=True)
        return
    all_audio_indices = {str(a["index"]) for a in sel["audios"]}
    if set(sel["selected_audios"]) == all_audio_indices:
        sel["selected_audios"] = []
        await query.answer("All audio tracks deselected.")
    else:
        sel["selected_audios"] = list(all_audio_indices)
        await query.answer("All audio tracks selected.")
    markup = build_audio_menu_markup(sel, job_id, int(user_id_str))
    try:
        await query.message.edit_reply_markup(reply_markup=markup)
    except MessageNotModified:
        return


@dtbot.on_callback_query(filters.regex("^vidsel_"))
async def callback_video_select(bot, query):
    (_, user_id_str, job_id, idx_str) = query.data.split("_")
    chat_id = query.message.chat.id
    sel = pending_states.get(chat_id, {}).get(job_id)
    if not sel:
        await query.answer("This recording session has expired!", show_alert=True)
        return
    sel["selected_video"] = next(
        (v for v in sel["videos"] if str(v["index"]) == idx_str), None
    )
    buttons = []
    user_id = int(user_id_str)
    for a in sel["audios"]:
        lang = a.get("language", "und")
        buttons.append(
            [
                InlineKeyboardButton(
                    f"🔊 {lang} (a{a['index']})",
                    callback_data=f"audsel_{user_id}_{job_id}_{a['index']}",
                )
            ]
        )
    buttons.append(
        [
            InlineKeyboardButton(
                "🎶 Select All Tracks", callback_data=f"audall_{user_id}_{job_id}"
            )
        ]
    )
    buttons.append(
        [
            InlineKeyboardButton(
                "✅ Done (Start Recording)", callback_data=f"done_{user_id}_{job_id}"
            )
        ]
    )
    buttons.append(
        [
            InlineKeyboardButton(
                "❌ Cancel Setup", callback_data=f"cancel_{user_id}_{job_id}"
            )
        ]
    )
    await query.message.edit_text(
        f"**Video Selected.** Now select one or more audio tracks for Job `{job_id[:8]}`.",
        reply_markup=InlineKeyboardMarkup(buttons),
    )
    await query.answer()


def build_audio_menu_markup(sel, job_id, user_id):
    """Builds the inline keyboard for audio track selection."""
    buttons = []
    for a in sel["audios"]:
        is_selected = str(a["index"]) in sel["selected_audios"]
        emoji = "✅" if is_selected else "🔊"
        lang = a.get("language", "und")
        buttons.append(
            [
                InlineKeyboardButton(
                    f"{emoji} {lang} (a{a['index']})",
                    callback_data=f"audsel_{user_id}_{job_id}_{a['index']}",
                )
            ]
        )
    buttons.append(
        [
            InlineKeyboardButton(
                "🎶 Select All / None", callback_data=f"audall_{user_id}_{job_id}"
            )
        ]
    )
    buttons.append(
        [
            InlineKeyboardButton(
                "✅ Done (Start Recording)", callback_data=f"done_{user_id}_{job_id}"
            )
        ]
    )
    buttons.append(
        [
            InlineKeyboardButton(
                "❌ Cancel Setup", callback_data=f"cancel_{user_id}_{job_id}"
            )
        ]
    )
    return InlineKeyboardMarkup(buttons)


@dtbot.on_callback_query(filters.regex("^audsel_"))
async def callback_audio_select(bot, query):
    """Handles individual audio track selection."""
    (_, user_id_str, job_id, idx_str) = query.data.split("_")
    chat_id = query.message.chat.id
    sel = pending_states.get(chat_id, {}).get(job_id)
    if not sel:
        await query.answer("This recording session has expired!", show_alert=True)
        return
    if idx_str in sel["selected_audios"]:
        sel["selected_audios"].remove(idx_str)
    else:
        sel["selected_audios"].append(idx_str)
    markup = build_audio_menu_markup(sel, job_id, int(user_id_str))
    try:
        await query.message.edit_reply_markup(reply_markup=markup)
        await query.answer("Audio selection updated.")
    except MessageNotModified:
        await query.answer("Audio selection updated.")


@dtbot.on_callback_query(filters.regex("^done_"))
async def callback_done(bot, query):
    (_, user_id_str, job_id) = query.data.split("_")
    chat_id = query.message.chat.id
    sel = pending_states.get(chat_id, {}).get(job_id)
    if not sel:
        await query.answer("This recording session has expired!", show_alert=True)
        return
    if not sel["selected_video"]:
        await query.answer("You must select a video track!", show_alert=True)
        return
    sel["status"] = "Queued ⌛"
    job_details = {
        "chat_id": chat_id,
        "job_id": job_id,
        "url": sel["url"],
        "duration": sel["duration"],
        "filename": sel["filename"],
        "video": sel["selected_video"],
        "audios": sel["selected_audios"],
        "msg_id": sel["msg_id"],
        "original_message_id": sel.get("original_message_id"),
        "use_header": sel.get("use_header", False),
    }
    await job_queue.put(job_details)
    user_id = int(user_id_str)
    await query.message.edit_text(
        f"✅ **Job `{job_id[:8]}` has been added to the queue!**\n\nYour recording will start as soon as a worker is free.",
        reply_markup=InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "❌ Cancel Queued Job",
                        callback_data=f"cancel_{user_id}_{job_id}",
                    )
                ]
            ]
        ),
    )
    await query.answer("Job queued!")


@dtbot.on_message(filters.command("start"))
async def start_cmd(bot, message):
    if message.text and len(message.text.split()) > 1:
        payload = message.text.split(maxsplit=1)[1]
        if payload.startswith("verify_"):
            user_id = message.from_user.id
            LOG.info(
                f"Received /start with verification payload: {payload} from user {user_id}"
            )
            if await complete_verification_integrated(bot, user_id, payload):
                await message.reply_text(
                    "🎉 You've been successfully verified! Get ready to record! 🚀",
                    parse_mode=enums.ParseMode.HTML,
                )
            else:
                await message.reply_text(
                    "❌ Your verification link is invalid or expired. Please request a new one using /verify. 🙁",
                    parse_mode=enums.ParseMode.HTML,
                )
            return
    welcome_message = (
        f"👋 Hi <b>{escape_html(message.from_user.first_name)}!</b> I'm your M3U8 Recorder Bot. Ready to capture your favorite streams! 🎬<br><br>\n"
        f"I can record streams from M3U8 links or our predefined channels. ✨<br><br>\n"
        f"<b>To record:</b><br>\n"
        f"<code>/rec \"[URL/Channel Name]\" [HH:MM:SS] [Optional Filename] [.L# (optional)]</code><br>\n"
        f"Example: <code>/rec \"Disney Channel (4K)\" 00:00:10 \"My Cartoon\" .L1</code><br>\n"
        f"For custom URL: <code>/rec \"https://example.com/stream.m3u8\" 00:05:00 \"My Stream\"</code><br><br>\n"
        f"Use <code>/help</code> to see all available commands. Let's get started! 🚀This Bot is Built by @Dora_Toonz @Shan_0103"
    )
    keyboard = [
        [
            InlineKeyboardButton("🧑‍💻 Developer", url="https://t.me/Shan_0103"),
            InlineKeyboardButton("📢 Developer Channel", url="https://t.me/Dora_Toonz"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await message.reply_text(
        welcome_message,
        reply_markup=reply_markup,
        parse_mode=enums.ParseMode.HTML,
        disable_web_page_preview=True,
    )


@dtbot.on_message(filters.command("help"))
async def help_cmd(bot, message):
    user_id = message.from_user.id
    help_text = (
        "📚 <b>Available Commands:</b><br><br>\n"
        "🔹 <code>/start</code> - Start the bot and get a welcome message. 👋<br>\n"
        "🔹 <code>/help</code> - Display this help message. 📖<br>\n"
        "🔹 <code>/status</code> - Check your current user status and recording limits. 📊<br>\n"
        "🔹 <code>/rec</code> - Start a new recording. Usage: <code>/rec \"[URL/Channel]\" [HH:MM:SS] [Optional Filename] [.L#]</code> 🎬<br>\n"
        "🔹 <code>/mytasks</code> - See your active recording tasks. 📋<br>\n"
        "🔹 <code>/cancel &lt;task_id&gt;</code> - Cancel a specific recording task. If no ID, I'll list yours. 🛑<br>\n"
        "🔹 <code>/channel</code> - Browse available M3U8 channel lists. 📺<br>\n"
        "🔹 <code>/search &lt;query&gt;</code> - Search for channels by name or description. 🔍<br>\n"
    )
    if config.ENABLE_SHORTLINK:
        help_text += "🔹 <code>/verify</code> - Get a link to verify for recording access (if required). 🔑<br>\n"
    if is_admin(user_id):
        help_text += (
            "<br>\n<b>🛠 Admin Commands:</b><br>\n"
            "🔹 <code>/tasks</code> - See all active recording tasks. 🌐<br>\n"
            "🔹 <code>/auth &lt;user_id&gt; &lt;duration&gt;</code> - Grant premium access (e.g., <code>30d</code>, <code>48h</code>). 💎<br>\n"
            "🔹 <code>/deauth &lt;user_id&gt;</code> - Revoke premium access. 🗑️<br>\n"
            "🔹 <code>/add_m3u8</code> - Add a new M3U8 channel list. ➕<br>\n"
            "🔹 <code>/remove_m3u8 &quot;json_name&quot;</code> - Remove an M3U8 channel list. ➖<br>\n"
            "🔹 <code>/pull [m3u8|log|premium|admin]</code> - Pull bot data. 📥<br>\n"
            "🔹 <code>/add_admin &lt;user_id&gt;</code> - Add a user as an admin. 👑<br>\n"
            "🔹 <code>/remove_admin &lt;user_id&gt;</code> - Remove a user from admin. ⚔️<br>\n"
            "🔹 <code>/flog [file|msg] &lt;task_id&gt;</code> - Get FFmpeg logs for a task. 📄<br>\n"
        )
    await message.reply_text(help_text, parse_mode=enums.ParseMode.HTML)


@dtbot.on_message(filters.command("status"))
async def status_cmd(bot, message):
    user_id = message.from_user.id
    tier_details = get_user_tier_details(user_id)
    tz = pytz.timezone(config.TIMEZONE)
    status_message = (
        f"👤 <b>Your Current Status:</b> ✨<br><br>\n"
        f"🔹 <b>User ID:</b> <code>{user_id}</code><br>\n"
        f"🔹 <b>Tier:</b> <code>{escape_html(tier_details['tier_name'])}</code><br>\n"
    )
    if tier_details["is_premium"]:
        record = premium_users_collection.find_one({"_id": user_id})
        expires_at = record.get("expires_at", 0) if record else 0
        expiry_datetime_str = (
            datetime.fromtimestamp(expires_at, tz).strftime("%Y-%m-%d %I:%M:%S %p")
            if expires_at > time.time()
            else "Expired"
        )
        status_message += f"🔹 <b>Premium Status:</b> Active (Expires: <code>{escape_html(expiry_datetime_str)}</code>) 💎<br>\n"
    if config.ENABLE_SHORTLINK:
        if tier_details["is_verified"]:
            record = verification_tokens_collection.find_one({"_id": user_id})
            expires_at = record.get("expires_at", 0) if record else 0
            expiry_datetime_str = (
                datetime.fromtimestamp(expires_at, tz).strftime("%Y-%m-%d %I:%M:%S %p")
                if expires_at > time.time()
                else "Expired"
            )
            status_message += f"🔹 <b>Verification:</b> Verified (Expires: <code>{escape_html(expiry_datetime_str)}</code>) ✅<br>\n"
        else:
            status_message += "🔹 <b>Verification:</b> Not Verified. Use <code>/verify</code>. 🚫<br>\n"
    status_message += "<br>\n<b>Current Limits:</b> 📏<br>\n"
    max_duration_display = (
        str(timedelta(seconds=int(tier_details["max_duration_sec"])))
        if tier_details["max_duration_sec"] != float("inf")
        else "Unlimited ♾️"
    )
    max_user_tasks_display = (
        tier_details["max_user_tasks"]
        if tier_details["max_user_tasks"] != float("inf")
        else "Unlimited ♾️"
    )
    status_message += f"🔹 <b>Max Recording Duration:</b> <code>{max_duration_display}</code><br>\n"
    status_message += f"🔹 <b>Max Parallel Tasks for You:</b> <code>{max_user_tasks_display}</code><br>\n"
    await message.reply_text(status_message, parse_mode=enums.ParseMode.HTML)


def build_tasks_pagination_markup(current_page, total_pages, user_id):
    """Builds the pagination buttons with the corrected data format."""
    buttons = []
    row = []
    base_callback = f"taskspage_{user_id}"
    if current_page > 0:
        row.append(
            InlineKeyboardButton(
                "⬅️ Previous", callback_data=f"{base_callback}_{current_page - 1}"
            )
        )
    if current_page < total_pages - 1:
        row.append(
            InlineKeyboardButton(
                "Next ➡️", callback_data=f"{base_callback}_{current_page + 1}"
            )
        )
    if row:
        buttons.append(row)
    return InlineKeyboardMarkup(buttons) if buttons else None


@dtbot.on_message(filters.command("tasks"))
async def tasks_cmd(bot, message):
    """Shows the first page of all active tasks with pagination and expiry."""
    all_tasks = get_all_active_tasks()
    if not all_tasks:
        await message.reply(
            "📊 <b>No active recording tasks.</b>", parse_mode=enums.ParseMode.HTML
        )
        return
    total_pages = (
        len(all_tasks) + config.STATUS_PAGE_SIZE - 1
    ) // config.STATUS_PAGE_SIZE
    current_page = 0
    start_index = current_page * config.STATUS_PAGE_SIZE
    tasks_for_page = all_tasks[start_index : start_index + config.STATUS_PAGE_SIZE]
    text = await build_tasks_output(tasks_for_page, current_page + 1, total_pages)
    markup = build_tasks_pagination_markup(
        current_page, total_pages, message.from_user.id
    )
    sent_message = await message.reply_text(
        text, reply_markup=markup, parse_mode=enums.ParseMode.HTML
    )
    asyncio.create_task(
        schedule_menu_expiry(sent_message.chat.id, sent_message.id, delay=180)
    )


async def schedule_menu_expiry(chat_id, message_id, delay=180):
    """Waits for a delay and then edits a message to show it has expired."""
    await asyncio.sleep(delay)
    try:
        await dtbot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text="📊 **Task list expired.**\n\nPlease use the `/tasks` command again.",
            reply_markup=None,
        )
    except Exception:
        return


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("taskspage_"))
)
@user_is_requester
async def tasks_pagination_cb(bot, query):
    """Handles the button clicks for task pagination."""
    try:
        (_, user_id_str, page_str) = query.data.split("_")
        user_id = int(user_id_str)
        current_page = int(page_str)
    except (ValueError, IndexError):
        await query.answer("Invalid button format.", show_alert=True)
        return
    all_tasks = get_all_active_tasks()
    if not all_tasks:
        await query.answer("No active tasks found.", show_alert=True)
        await query.message.delete()
        return
    total_pages = (
        len(all_tasks) + config.STATUS_PAGE_SIZE - 1
    ) // config.STATUS_PAGE_SIZE
    current_page = max(0, min(current_page, total_pages - 1))
    start_index = current_page * config.STATUS_PAGE_SIZE
    tasks_for_page = all_tasks[start_index : start_index + config.STATUS_PAGE_SIZE]
    text = await build_tasks_output(tasks_for_page, current_page + 1, total_pages)
    markup = build_tasks_pagination_markup(
        current_page, total_pages, query.from_user.id
    )
    try:
        await query.message.edit_text(
            text, reply_markup=markup, parse_mode=enums.ParseMode.HTML
        )
    except MessageNotModified:
        pass
    await query.answer()


def get_all_active_tasks():
    """Gets a list of all active tasks by reading their state directly."""
    all_tasks = []
    for (chat_id, jobs) in pending_states.items():
        for (job_id, details) in jobs.items():
            if details.get("cancelled"):
                continue
            all_tasks.append(
                {
                    "id": job_id,
                    "user_id": details.get("user_id"),
                    "chat_id": chat_id,
                    "progress_message_id": details.get("msg_id"),
                    "filename": os.path.basename(details.get("filename", "N/A")),
                    "target": format_duration_hhmmss(details.get("duration", 0)),
                    "status": details.get("status", "Unknown ❓"),
                }
            )
    return all_tasks


@dtbot.on_message(filters.command("mytasks"))
async def mytasks_cmd(client, message):
    user_id = message.from_user.id
    all_tasks = get_all_active_tasks()
    my_tasks_list = [task for task in all_tasks if task.get("user_id") == user_id]
    if not my_tasks_list:
        await message.reply(
            "🚀 <b>You have no active recording tasks.</b>",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    tasks_text_content = await build_tasks_output(my_tasks_list, 1, 1)
    await message.reply(tasks_text_content, parse_mode=enums.ParseMode.HTML)


@dtbot.on_message(filters.command("flog"))
@admin_only
async def get_ffmpeg_log(bot, message):
    if len(message.command) < 3:
        await message.reply_text(
            "<b>Usage:</b>\n• `/flog file <task_id>` - Sends the full log file.\n• `/flog msg <task_id>` - Shows the last 50 lines."
        )
        return
    mode = message.command[1].lower()
    job_id = message.command[2]
    if mode not in ("file", "msg"):
        await message.reply_text("❌ Invalid mode. Use `file` or `msg`.")
        return
    log_file_path = os.path.join(FLOG_DIR, f"{job_id}.txt")
    if not os.path.exists(log_file_path):
        await message.reply_text(f"❌ Log file for Task ID `{job_id}` not found.")
        return
    try:
        if mode == "file":
            await message.reply_document(
                document=log_file_path,
                caption=f"📋 FFmpeg log for Task ID `{job_id}`",
            )
            return
        if mode == "msg":
            async with aiofiles.open(log_file_path, "r", encoding="utf-8") as f:
                lines = await f.readlines()
            last_lines = lines[-50:]
            if not last_lines:
                await message.reply_text(f"Log file for `{job_id}` is empty.")
                return
            response_text = f"📝 **Last 50 lines of FFmpeg log for `{job_id}`:**\n\n"
            response_text += f"<code>{''.join(last_lines)}</code>"
            if len(response_text) > 4096:
                response_text = response_text[:4090] + "..."
            await message.reply_text(response_text)
    except Exception as e:
        await message.reply_text(f"An error occurred: {e}")


@dtbot.on_message(filters.command("cancel"))
async def cancel_cmd(bot, message):
    """Shows a user their running/queued jobs to cancel."""
    user_id = message.from_user.id
    buttons = []
    for (job_id, proc) in running_jobs.items():
        for (chat_id, jobs) in pending_states.items():
            if job_id in jobs and jobs[job_id].get("msg_id"):
                try:
                    original_msg = await bot.get_messages(
                        chat_id, jobs[job_id]["msg_id"]
                    )
                    if original_msg.reply_to_message.from_user.id == user_id:
                        fname = os.path.basename(jobs[job_id]["filename"])
                        buttons.append(
                            [
                                InlineKeyboardButton(
                                    f"🔴Running: {fname} (ID: {job_id})",
                                    callback_data=f"cancel_{job_id}",
                                )
                            ]
                        )
                except Exception:
                    continue
    for item in job_queue._queue:
        try:
            original_msg = await bot.get_messages(item["chat_id"], item["msg_id"])
            if original_msg.reply_to_message.from_user.id == user_id:
                fname = os.path.basename(item["filename"])
                buttons.append(
                    [
                        InlineKeyboardButton(
                            f"🟡Queued: {fname} (ID: {item['job_id']})",
                            callback_data=f"cancel_{item['job_id']}",
                        )
                    ]
                )
        except Exception:
            continue
    if not buttons:
        await message.reply_text("You have no active or queued jobs to cancel.")
        return
    await message.reply_text(
        "Select a job to cancel:", reply_markup=InlineKeyboardMarkup(buttons)
    )


@dtbot.on_callback_query(filters.regex("^cancel_"))
@requester_or_admin
async def callback_cancel(bot, query):
    """Handles all job cancellation requests from the original user or an admin."""
    parts = query.data.split("_")
    job_id = parts[-1]
    job_found_and_removed = False
    try:
        if job_id in running_jobs:
            running_jobs[job_id].terminate()
            await query.answer("Cancelling running job...", show_alert=False)
            await query.message.edit_text("✅ Recording cancellation is in progress...")
            job_found_and_removed = True
        else:
            queue_items = list(job_queue._queue)
            job_queue._queue.clear()
            found_in_queue = False
            for item in queue_items:
                if item["job_id"] == job_id:
                    found_in_queue = True
                    continue
                await job_queue.put(item)
            if found_in_queue:
                await query.answer("Job removed from queue.", show_alert=True)
                await query.message.edit_text(
                    "❌ Recording job was cancelled from the queue."
                )
                job_found_and_removed = True
        if not job_found_and_removed:
            for (chat_id, jobs) in pending_states.items():
                if job_id in jobs:
                    jobs[job_id]["cancelled"] = True
                    await query.answer("Setup cancelled.", show_alert=True)
                    await query.message.edit_text("❌ Recording setup was cancelled.")
                    job_found_and_removed = True
                    break
        if not job_found_and_removed:
            await query.answer(
                "Job not found or already completed/cancelled.", show_alert=True
            )
    finally:
        for (chat_id, jobs) in list(pending_states.items()):
            if job_id in jobs:
                job_dir = os.path.dirname(jobs[job_id]["filename"])
                if os.path.exists(job_dir):
                    shutil.rmtree(job_dir, ignore_errors=True)
                    LOG.info(f"Cleaned up directory for cancelled job {job_id}")
                del pending_states[chat_id][job_id]
                LOG.info(f"Removed state for cancelled job {job_id}")
                break


@dtbot.on_message(filters.command("auth"))
@admin_only
async def auth_user_cmd(bot, message):
    user_to_auth = None
    if message.reply_to_message:
        user_to_auth = message.reply_to_message.from_user
    args = shlex.split(message.text)
    if len(args) < 2:
        await message.reply(
            "💡 <b>Usage:</b> Reply to a user with <code>/auth &lt;duration&gt;</code> (e.g., 30d, 48h)."
        )
        return
    duration_str = args[1]
    if not user_to_auth:
        await message.reply("Please reply to a user's message to authorize them.")
        return
    try:
        duration_seconds = 0
        if duration_str.endswith("d"):
            duration_seconds = int(duration_str[:-1]) * 24 * 3600
        elif duration_str.endswith("h"):
            duration_seconds = int(duration_str[:-1]) * 3600
        else:
            await message.reply(
                "❌ Invalid duration format. Use 'd' for days or 'h' for hours."
            )
            return
        if duration_seconds <= 0:
            await message.reply("❌ Duration must be positive.")
            return
        expires_at = int(time.time()) + duration_seconds
        user_info = {
            "is_premium": True,
            "expires_at": expires_at,
            "name": (user_to_auth.first_name + f" {user_to_auth.last_name}")
            if user_to_auth.last_name
            else user_to_auth.first_name,
            "username": user_to_auth.username,
        }
        premium_users_collection.update_one(
            {"_id": user_to_auth.id}, {"$set": user_info}, upsert=True
        )
        expiry_date_str = datetime.fromtimestamp(
            expires_at, pytz.timezone("Asia/Kolkata")
        ).strftime("%Y-%m-%d %I:%M %p")
        await message.reply(
            f"✅ User {user_to_auth.mention} has been granted premium access for <b>{duration_str}</b>.\nExpires: <code>{expiry_date_str}</code>"
        )
    except Exception as e:
        await message.reply(f"An error occurred: {e}")


@dtbot.on_message(filters.command("deauth"))
@admin_only
async def deauth_user_cmd(bot, message):
    user_id = None
    target_user = (
        message.reply_to_message.from_user if message.reply_to_message else None
    )
    try:
        if target_user:
            user_id = target_user.id
        else:
            args = message.text.split(maxsplit=1)
            if len(args) > 1 and args[1].isdigit():
                user_id = int(args[1])
        if not user_id:
            raise ValueError("User ID not provided")
        if is_owner(user_id):
            await message.reply_text(
                "❌ You cannot deauthorize the bot owner.",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        result = premium_users_collection.delete_one({"_id": user_id})
        if result.deleted_count > 0:
            await message.reply(
                f"✅ <b>Premium access revoked for user <code>{user_id}</code>.</b>",
                parse_mode=enums.ParseMode.HTML,
            )
            try:
                await bot.send_message(
                    user_id,
                    "😔 Your <b>Premium access</b> has been revoked.",
                    parse_mode=enums.ParseMode.HTML,
                )
            except Exception as e:
                LOG.warning(
                    f"Could not notify user {user_id} about premium revocation: {e}"
                )
        else:
            await message.reply(
                f"ℹ️ <b>User <code>{user_id}</code> was not found in the premium list.</b>",
                parse_mode=enums.ParseMode.HTML,
            )
    except (ValueError, IndexError):
        await message.reply(
            "💡 <b>Usage:</b> <code>/deauth &lt;user_id&gt;</code> or reply to a user's message.",
            parse_mode=enums.ParseMode.HTML,
        )
    except Exception as e:
        LOG.error(f"Error in /deauth command: {e}", exc_info=True)
        await message.reply(
            "❌ An unexpected error occurred.", parse_mode=enums.ParseMode.HTML
        )


@dtbot.on_message(filters.command("add_admin"))
@owner_only
async def add_admin_cmd(bot, message):
    user_id = None
    target_user = (
        message.reply_to_message.from_user if message.reply_to_message else None
    )
    if target_user:
        user_id = target_user.id
    else:
        args = message.text.split(" ", 1)
        if len(args) > 1 and args[1].isdigit():
            user_id = int(args[1])
    if not user_id:
        await message.reply_text(
            "💡 <b>Usage:</b> <code>/add_admin &lt;user_id&gt;</code> or reply to a user.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    if is_admin(user_id):
        await message.reply_text(
            f"⚠️ User <code>{user_id}</code> is already an admin.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    admin_users_collection.update_one(
        {"_id": user_id}, {"$set": {"is_admin": True}}, upsert=True
    )
    await message.reply_text(
        f"👑 <b>User <code>{user_id}</code> is now an Admin.</b>",
        parse_mode=enums.ParseMode.HTML,
    )
    try:
        await bot.send_message(
            user_id,
            "🎉 You have been granted <b>Admin privileges</b>! Use your new powers wisely.",
            parse_mode=enums.ParseMode.HTML,
        )
    except Exception as e:
        LOG.warning(f"Could not notify user {user_id} about admin access: {e}")


@dtbot.on_message(filters.command("remove_admin"))
@owner_only
async def remove_admin_cmd(bot, message):
    user_id = None
    target_user = (
        message.reply_to_message.from_user if message.reply_to_message else None
    )
    if target_user:
        user_id = target_user.id
    else:
        args = message.text.split(" ", 1)
        if len(args) > 1 and args[1].isdigit():
            user_id = int(args[1])
    if not user_id:
        await message.reply_text(
            "💡 <b>Usage:</b> <code>/remove_admin &lt;user_id&gt;</code> or reply to a user.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    if user_id == config.OWNER_ID:
        await message.reply_text(
            "❌ The owner's admin status cannot be revoked.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    if not admin_users_collection.find_one({"_id": user_id}):
        await message.reply_text(
            f"⚠️ User <code>{user_id}</code> is not an admin.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    admin_users_collection.delete_one({"_id": user_id})
    await message.reply_text(
        f"🗑️ <b>User <code>{user_id}</code> has been removed from Admin.</b>",
        parse_mode=enums.ParseMode.HTML,
    )
    try:
        await bot.send_message(
            user_id,
            "😔 Your <b>Admin privileges</b> have been revoked.",
            parse_mode=enums.ParseMode.HTML,
        )
    except Exception as e:
        LOG.warning(f"Could not notify user {user_id} about admin revocation: {e}")


@dtbot.on_message(filters.command("add_m3u8"))
@admin_only
async def add_m3u8_cmd(bot, message):
    os.makedirs(config.M3U8_FILES_DIRECTORY, exist_ok=True)
    if message.reply_to_message and message.reply_to_message.document:
        doc = message.reply_to_message.document
        if not doc.file_name.lower().endswith(".json"):
            await message.reply(
                "❌ <b>Invalid File:</b> Please reply to a <code>.json</code> file.",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        file_path_final = os.path.join(config.M3U8_FILES_DIRECTORY, doc.file_name)
        try:
            await message.reply_to_message.download(file_path_final)
            await message.reply(
                f"✅ <b>M3U8 list <code>{escape_html(doc.file_name)}</code> added successfully!</b>",
                parse_mode=enums.ParseMode.HTML,
            )
        except Exception as e:
            LOG.error(f"Error adding M3U8 file: {e}", exc_info=True)
            await message.reply(
                f"❌ <b>Error adding file:</b> <code>{escape_html(str(e))}</code>",
                parse_mode=enums.ParseMode.HTML,
            )
        return
    try:
        command_args = shlex.split(message.text.split(maxsplit=1)[1])
        if len(command_args) != 4:
            raise ValueError("Invalid number of arguments.")
        (json_name_raw, link, channel_name, group_name) = command_args
        json_filename = (
            f"{sanitize_filename(json_name_raw.lower().replace(' ', '_'))}.json"
        )
        filepath = os.path.join(config.M3U8_FILES_DIRECTORY, json_filename)
        channels_data = {}
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                channels_data = json.load(f)
        channel_key = sanitize_filename(channel_name.lower().replace(" ", ""))
        channels_data[channel_key] = {
            "name": channel_name,
            "url": link,
            "Group": group_name,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(channels_data, f, indent=4)
        await message.reply(
            f"✅ Channel '<b>{escape_html(channel_name)}</b>' added to list <code>{escape_html(json_filename)}</code>.",
            parse_mode=enums.ParseMode.HTML,
        )
    except Exception:
        await message.reply(
            '<b>💡 Usage:</b>\n1. Reply to a <code>.json</code> file with <code>/add_m3u8</code>.\n2. Use inline: <code>/add_m3u8 "json name" "url" "channel name" "group"</code>',
            parse_mode=enums.ParseMode.HTML,
        )


@dtbot.on_message(filters.command("remove_m3u8"))
@admin_only
async def remove_m3u8_cmd(bot, message):
    try:
        args = shlex.split(message.text.split(maxsplit=1)[1])
        if not args:
            raise ValueError("Filename not provided")
        json_name_raw = args[0]
        if not json_name_raw.lower().endswith(".json"):
            json_filename = f"{sanitize_filename(json_name_raw)}.json"
        else:
            json_filename = sanitize_filename(json_name_raw)
        filepath = os.path.join(config.M3U8_FILES_DIRECTORY, json_filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            await message.reply(
                f"✅ M3U8 list <code>{escape_html(json_filename)}</code> removed successfully!",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        await message.reply(
            f"ℹ️ M3U8 list <code>{escape_html(json_filename)}</code> not found.",
            parse_mode=enums.ParseMode.HTML,
        )
    except Exception:
        await message.reply(
            '💡 <b>Usage:</b> <code>/remove_m3u8 "filename.json"</code>',
            parse_mode=enums.ParseMode.HTML,
        )


def build_button_rows(buttons, max_cols=2):
    """Builds rows of buttons with a max number of columns."""
    return [buttons[i : i + max_cols] for i in range(0, len(buttons), max_cols)]


@dtbot.on_message(filters.command("channel"))
async def channel_cmd(bot, message):
    """Handles the /channel command and shows the main list of M3U8 files."""
    channels_data = load_m3u8_channels()
    if not channels_data:
        await message.reply(
            "🏜️ <b>No M3U8 channel lists found.</b>",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    requester_id = message.from_user.id
    markup_rows = []
    for (i, list_name) in enumerate(sorted(channels_data.keys()), 1):
        display_name = escape_html(list_name.replace("_", " ").title())
        callback_data = f"showlist_{requester_id}_{list_name}_0"
        markup_rows.append(
            [InlineKeyboardButton(f"L{i}: {display_name}", callback_data=callback_data)]
        )
    await message.reply(
        f"📺 <b>Available Channel Lists</b>\n\n<i>(Menu for <code>{requester_id}</code>)</i>",
        reply_markup=InlineKeyboardMarkup(markup_rows),
        parse_mode=enums.ParseMode.HTML,
    )


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("showlist_"))
)
@user_is_requester
async def show_list_callback(bot, query):
    """Handles the selection of a list and shows the groups inside it."""
    try:
        (prefix, requester_id_str, list_name, page_str) = query.data.split("_", 3)
        requester_id, page = (int(requester_id_str), int(page_str))
    except ValueError:
        await query.answer("Invalid button format.", show_alert=True)
        return
    channels_in_list = load_m3u8_channels().get(list_name)
    if not channels_in_list:
        await query.answer("List not found.", show_alert=True)
        return
    all_groups = sorted(
        list({d.get("Group", "Uncategorized") for d in channels_in_list.values()})
    )
    total_pages = (len(all_groups) + CHANNELS_PER_PAGE - 1) // CHANNELS_PER_PAGE
    paginated_groups = all_groups[
        page * CHANNELS_PER_PAGE : (page + 1) * CHANNELS_PER_PAGE
    ]
    group_buttons = [
        InlineKeyboardButton(
            f"📁 {g}", callback_data=f"showgroup_{requester_id}_{list_name}_{g}_0"
        )
        for g in paginated_groups
    ]
    markup_rows = build_button_rows(group_buttons)
    nav_buttons = []
    if page > 0:
        nav_buttons.append(
            InlineKeyboardButton(
                "⬅️",
                callback_data=f"showlist_{requester_id}_{list_name}_{page - 1}",
            )
        )
    if page < total_pages - 1:
        nav_buttons.append(
            InlineKeyboardButton(
                "➡️",
                callback_data=f"showlist_{requester_id}_{list_name}_{page + 1}",
            )
        )
    bottom_row = [
        InlineKeyboardButton("🔙 Back", callback_data=f"backlists_{requester_id}"),
        InlineKeyboardButton(
            "📦 All Channels",
            callback_data=f"showall_{requester_id}_{list_name}_0",
        ),
    ]
    if nav_buttons:
        markup_rows.append(nav_buttons)
    markup_rows.append(bottom_row)
    await query.message.edit_text(
        f"📁 <b>Groups in '{escape_html(list_name)}'</b> (Page {page + 1}/{total_pages})\n\n<i>(Menu for <code>{requester_id}</code>)</i>",
        reply_markup=InlineKeyboardMarkup(markup_rows),
        parse_mode=enums.ParseMode.HTML,
    )
    await query.answer()


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("showgroup_"))
)
@user_is_requester
async def show_group_callback(bot, query):
    """Handles showing channels within a specific group, with correct formatting."""
    try:
        (prefix, requester_id_str, list_name, group_name, page_str) = query.data.split(
            "_", 4
        )
        page = int(page_str)
        requester_id = int(requester_id_str)
    except ValueError:
        await query.answer("Invalid button format.", show_alert=True)
        return
    all_list_names = sorted(load_m3u8_channels().keys())
    list_number = (
        all_list_names.index(list_name) + 1 if list_name in all_list_names else "N/A"
    )
    channels_in_list = load_m3u8_channels().get(list_name, {})
    group_channels = sorted(
        [d for d in channels_in_list.values() if d.get("Group") == group_name],
        key=lambda d: d.get("name", ""),
    )
    CHANNELS_PER_DETAILED_PAGE = 5
    total_pages = (
        len(group_channels) + CHANNELS_PER_DETAILED_PAGE - 1
    ) // CHANNELS_PER_DETAILED_PAGE
    paginated_channels = group_channels[
        page * CHANNELS_PER_DETAILED_PAGE : (page + 1) * CHANNELS_PER_DETAILED_PAGE
    ]
    channel_text_parts = [
        f"🔹 <b>Name:</b> <code>{escape_html(c.get('name', 'N/A'))}</code>\n🔹 <b>Group:</b> <code>{escape_html(c.get('Group', 'N/A'))}</code>"
        for c in paginated_channels
    ]
    channel_text = "\n----------------------------------\n".join(channel_text_parts)
    rows = []
    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                "⬅️",
                callback_data=f"showgroup_{requester_id}_{list_name}_{group_name}_{page - 1}",
            )
        )
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton(
                "➡️",
                callback_data=f"showgroup_{requester_id}_{list_name}_{group_name}_{page + 1}",
            )
        )
    if nav:
        rows.append(nav)
    rows.append(
        [
            InlineKeyboardButton(
                "🔙 Back to Groups",
                callback_data=f"showlist_{requester_id}_{list_name}_0",
            )
        ]
    )
    header = f"📺 Channels in '{escape_html(list_name)}' [L{list_number}] ({escape_html(group_name)}) (Page {page + 1}/{total_pages}):"
    await query.message.edit_text(
        f"{header}\n\n{channel_text}",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=enums.ParseMode.HTML,
    )
    await query.answer()


@dtbot.on_callback_query(
    filters.regex(r"^show_list_(\d+)_([a-zA-Z0-9_-]+)_(\d+)$")
)
@user_is_requester
async def show_channels_callback(bot, query):
    (requester_id, list_name, page_str) = query.matches[0].groups()
    (requester_id, page) = (int(requester_id), int(page_str))
    channels_data = load_m3u8_channels()
    channels_in_list = channels_data.get(list_name)
    if not channels_in_list:
        await query.answer("List not found.", show_alert=True)
        return
    all_groups = list(
        {d.get("Group", "Uncategorized") for d in channels_in_list.values()}
    )
    total_pages = (len(all_groups) + CHANNELS_PER_PAGE - 1) // CHANNELS_PER_PAGE
    start_index = page * CHANNELS_PER_PAGE
    paginated_groups = all_groups[start_index : start_index + CHANNELS_PER_PAGE]
    group_buttons = [
        InlineKeyboardButton(
            f"📁 {g}", callback_data=f"show_group_{requester_id}_{list_name}_{g}_0"
        )
        for g in paginated_groups
    ]
    markup_rows = build_button_rows(group_buttons)
    nav_buttons = []
    if page > 0:
        nav_buttons.append(
            InlineKeyboardButton(
                "⬅️",
                callback_data=f"show_list_{requester_id}_{list_name}_{page - 1}",
            )
        )
    if page < total_pages - 1:
        nav_buttons.append(
            InlineKeyboardButton(
                "➡️",
                callback_data=f"show_list_{requester_id}_{list_name}_{page + 1}",
            )
        )
    bottom_row = [
        InlineKeyboardButton(
            "🔙 Back", callback_data=f"channel_list_back_{requester_id}"
        ),
        InlineKeyboardButton(
            "📦 All Channels",
            callback_data=f"show_all_{requester_id}_{list_name}_0",
        ),
    ]
    if nav_buttons:
        markup_rows.append(nav_buttons)
    markup_rows.append(bottom_row)
    await query.message.edit_text(
        f"📁 <b>Groups in '{escape_html(list_name)}'</b> (Page {page + 1}/{total_pages})\n\n<i>(Menu for <code>{requester_id}</code>)</i>",
        reply_markup=InlineKeyboardMarkup(markup_rows),
    )
    await query.answer()


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("backlists_"))
)
@user_is_requester
async def channel_list_back_callback(bot, query):
    class MockMessage:
        def __init__(self, user):
            self.from_user = user

        async def reply(self, text=None, reply_markup=None, parse_mode=None):
            await query.message.edit_text(
                text, reply_markup=reply_markup, parse_mode=parse_mode
            )

    await query.answer()
    await channel_cmd(bot, MockMessage(query.from_user))


@dtbot.on_message(filters.command("pull"))
@admin_only
async def pull_cmd(bot, message):
    args = message.text.split(maxsplit=1)
    pull_type = args[1].lower() if len(args) > 1 else None
    if not pull_type:
        await message.reply_text(
            "💡 <b>Usage:</b> <code>/pull [premium|m3u8|log|admin]</code>",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    if pull_type == "premium":
        now = int(time.time())
        premium_users_collection.delete_many({"expires_at": {"$lt": now}})
        active_premium_users = list(
            premium_users_collection.find({"is_premium": True})
        )
        if not active_premium_users:
            await message.reply_text("ℹ️ No active premium users found.")
            return
        response_text = "💰 <b>Active Premium Users:</b>\n\n"
        tz = pytz.timezone("Asia/Kolkata")
        for user in active_premium_users:
            expiry_date_str = datetime.fromtimestamp(
                user["expires_at"], tz
            ).strftime("%Y-%m-%d %I:%M %p")
            name = escape_html(user.get("name", f"User ID: {user['_id']}"))
            username = user.get("username")
            username_str = f"(@{username})" if username else ""
            response_text += (
                f"🔹 <b>{name}</b> <code>{username_str}</code>\n"
                f"   - ID: <code>{user['_id']}</code>\n"
                f"   - Expires: <code>{expiry_date_str}</code>\n"
                f"----------------------------------\n"
            )
        await message.reply_text(response_text, parse_mode=enums.ParseMode.HTML)
    elif pull_type == "m3u8":
        files = os.listdir(config.M3U8_FILES_DIRECTORY)
        if not files:
            await message.reply_text("ℹ️ <b>No M3U8 JSON files found.</b>")
            return
        await message.reply_text("📦 <b>Sending M3U8 JSON files...</b>")
        for filename in files:
            await message.reply_document(
                os.path.join(config.M3U8_FILES_DIRECTORY, filename)
            )
    elif pull_type == "log":
        if os.path.exists(LOG_FILENAME):
            await message.reply_document(
                LOG_FILENAME, caption="Here's the current bot log file."
            )
            return
        await message.reply_text("⚠️ Log file not found.")
    elif pull_type == "admin":
        admin_ids = {config.OWNER_ID}
        other_admins = admin_users_collection.find({})
        for admin in other_admins:
            admin_ids.add(admin["_id"])
        if not admin_ids:
            await message.reply_text("ℹ️ No admins configured or found in the database.")
            return
        response_text = "👑 <b>Admin Users:</b>\n\n"
        for user_id in sorted(list(admin_ids)):
            try:
                user = await bot.get_users(user_id)
                name = escape_html(user.first_name)
                username_str = (
                    f"<code>(@{user.username})</code>" if user.username else ""
                )
                owner_tag = " (<b>Bot Owner</b>)" if user_id == config.OWNER_ID else ""
                response_text += (
                    f"🔹 <b>{name}</b> <code>{username_str}</code>{owner_tag}\n"
                    f"    - ID: <code>{user_id}</code>\n"
                    f"----------------------------------\n"
                )
            except Exception as e:
                LOG.warning(f"Could not fetch details for admin ID {user_id}: {e}")
                owner_tag = (
                    " (<b>Bot Owner 👑</b>)" if user_id == config.OWNER_ID else ""
                )
                response_text += (
                    f"🔹 <i>Unknown User</i>{owner_tag}\n"
                    f"    - ID: <code>{user_id}</code> (Could not fetch details)\n"
                    f"----------------------------------\n"
                )
        await message.reply_text(
            response_text,
            parse_mode=enums.ParseMode.HTML,
            disable_web_page_preview=True,
        )
    else:
        await message.reply_text(
            "❌ <b>Invalid pull type.</b> Use <code>premium</code>, <code>m3u8</code>, <code>log</code>, or <code>admin</code>."
        )


@dtbot.on_callback_query(filters.regex("pull_all_m3u8_files_from_panel"))
@admin_only_cb
async def pull_all_m3u8_files_callback(bot, query):
    await query.answer("Preparing files...")
    await query.message.edit_text(
        "📦 <b>Sending M3U8 JSON files...</b>", parse_mode=enums.ParseMode.HTML
    )
    files = os.listdir(config.M3U8_FILES_DIRECTORY)
    if not files:
        await bot.send_message(
            query.message.chat.id,
            "ℹ️ <b>No M3U8 JSON files found.</b>",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    for filename in [f for f in files if f.endswith(".json")]:
        filepath = os.path.join(config.M3U8_FILES_DIRECTORY, filename)
        await bot.send_document(
            chat_id=query.message.chat.id,
            document=filepath,
            caption=f"<code>{escape_html(filename)}</code>",
            parse_mode=enums.ParseMode.HTML,
        )


@dtbot.on_message(filters.command("search"))
async def search_channel_cmd(bot, message):
    user_id = message.from_user.id
    try:
        args = shlex.split(message.text.split(maxsplit=1)[1])
        if not args:
            raise ValueError("No arguments provided")
        search_query = args[0].lower()
        list_specifiers = [s for s in args[1:] if s.lower().startswith(".l")]
    except (ValueError, IndexError):
        await message.reply(
            'Usage:\n- `/search "query"` (searches all lists)\n- `/search "query" .l1` (searches list 1)\n- `/search "query" .l1 .l3` (searches lists 1 and 3)',
            parse_mode=enums.ParseMode.HTML,
        )
        return
    channels_data = load_m3u8_channels()
    sorted_list_names = sorted(channels_data.keys())
    lists_to_search = {}
    if list_specifiers:
        target_list_names = set()
        for spec in list_specifiers:
            try:
                idx = int(spec[2:]) - 1
                if 0 <= idx < len(sorted_list_names):
                    target_list_names.add(sorted_list_names[idx])
                else:
                    await message.reply(
                        f"Invalid list specifier `{spec}`. It's out of range."
                    )
            except (ValueError, IndexError):
                await message.reply(f"Invalid list specifier format: `{spec}`.")
        if not target_list_names:
            await message.reply("No valid lists were selected for the search.")
            return
        lists_to_search = {name: channels_data[name] for name in target_list_names}
    else:
        lists_to_search = channels_data
    results = [
        {"list": lname, "name": d["name"], "group": d.get("Group", "N/A")}
        for lname, channels in lists_to_search.items()
        for d in channels.values()
        if search_query in d.get("name", "").lower()
    ]
    if not results:
        await message.reply(
            f"No channels found matching '`{escape_html(search_query)}`' in the selected lists.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    initial_message = await message.reply_text(
        "Searching...", parse_mode=enums.ParseMode.HTML
    )
    global_search_results[user_id] = {
        "query": search_query,
        "results": results,
        "message_id": initial_message.id,
    }
    await send_search_results_page(message.chat.id, initial_message.id, user_id, 0)


async def send_search_results_page(chat_id, message_id, user_id, page):
    search_data = global_search_results.get(user_id)
    if not search_data or search_data.get("message_id") != message_id:
        return
    results = search_data["results"]
    all_list_names = sorted(load_m3u8_channels().keys())
    RESULTS_PER_PAGE = 5
    total_pages = (len(results) + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
    page = max(0, min(page, total_pages - 1))
    paginated_results = results[
        page * RESULTS_PER_PAGE : (page + 1) * RESULTS_PER_PAGE
    ]
    response_parts = []
    for r in paginated_results:
        try:
            list_index = all_list_names.index(r["list"]) + 1
            list_tag = f"L{list_index}"
        except ValueError:
            list_tag = "N/A"
        response_parts.append(
            f"🔹 <b>Channel Name:</b> <code>{escape_html(r['name'])}</code>\n"
            f"🔹 <b>List:</b> {list_tag}\n"
            f"🔹 <b>Group:</b> <code>{escape_html(r['group'])}</code>"
        )
    response_text = "\n----------------------------------\n".join(response_parts)
    nav_buttons = []
    if page > 0:
        nav_buttons.append(
            InlineKeyboardButton(
                "⬅️ Prev", callback_data=f"searchpage_{user_id}_{page - 1}"
            )
        )
    if page < total_pages - 1:
        nav_buttons.append(
            InlineKeyboardButton(
                "Next ➡️", callback_data=f"searchpage_{user_id}_{page + 1}"
            )
        )
    markup = InlineKeyboardMarkup([nav_buttons]) if nav_buttons else None
    await dtbot.edit_message_text(
        chat_id,
        message_id,
        f"🔍 <b>Search Results for '<code>{escape_html(search_data['query'])}</code>'</b> (Page {page + 1}/{total_pages})\n\n{response_text}",
        reply_markup=markup,
        parse_mode=enums.ParseMode.HTML,
    )


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("searchpage_"))
)
@user_is_requester
async def search_pagination_cb(bot, query):
    try:
        (prefix, user_id_str, page_str) = query.data.split("_")
        user_id = int(user_id_str)
        page = int(page_str)
    except (ValueError, IndexError):
        await query.answer("Invalid button format.", show_alert=True)
        return
    if (
        user_id not in global_search_results
        or global_search_results[user_id].get("message_id") != query.message.id
    ):
        await query.answer("⚠️ This search has expired.", show_alert=True)
        return
    await send_search_results_page(query.message.chat.id, query.message.id, user_id, page)
    await query.answer()


@dtbot.on_message(filters.command("verify"))
async def verify_cmd(bot, message):
    user_id = message.from_user.id
    if is_admin(user_id) or is_premium_user(user_id):
        await message.reply(
            "✅ <b>You don't need verification.</b> You're an admin or premium user!",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    if not config.ENABLE_SHORTLINK:
        await message.reply(
            "⚠️ <b>Verification is currently disabled by the admin.</b>",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    await send_verification_message_integrated(bot, message)


@dtbot.on_message(filters.text & filters.private & ~filters.command([]))
async def handle_rec_title_message(bot, message):
    user_id = message.from_user.id
    if user_id in user_waiting_for_title:
        title_data = user_waiting_for_title.pop(user_id)
        raw_filename = message.text.strip()
        rec_command_parts = [
            "/rec",
            shlex.quote(title_data["input_identifier"]),
            title_data["timestamp_str"],
        ]
        if raw_filename:
            rec_command_parts.append(shlex.quote(raw_filename))
        if title_data["m3u8_list_specifier"]:
            rec_command_parts.append(title_data["m3u8_list_specifier"])
        rec_command_text = " ".join(rec_command_parts)
        mock_message = Message(
            id=title_data["initial_message_id"],
            chat=message.chat,
            from_user=message.from_user,
            text=rec_command_text,
            date=message.date,
        )
        await handle_rec_command(bot, mock_message)


@dtbot.on_message(filters.command("rec"))
async def handle_rec_command(bot, message):
    user_id = message.from_user.id
    if (
        message.chat.type != enums.ChatType.PRIVATE
        and message.chat.id != config.WORKING_GROUP
    ):
        await unauthorized_access(message)
        return
    user_type_details = get_user_tier_details(user_id)
    if user_type_details["max_user_tasks"] == 0:
        custom_message = "🔒 **Recording Access Required**\n\nYou currently don't have permission to start a recording.\n\nTo get free, temporary access, please use the <code>/verify</code> command and follow the instructions. ✨"
        await message.reply_text(custom_message, parse_mode=enums.ParseMode.HTML)
        return
    all_current_tasks = get_all_active_tasks()
    if len(all_current_tasks) >= config.GLOBAL_MAX_PARALLEL_TASKS:
        await message.reply_text(
            "⚠️ **System Busy**\n\nThe maximum number of global recordings is in progress. Please try again in a few minutes.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    user_running_tasks = [
        task for task in all_current_tasks if task.get("user_id") == user_id
    ]
    if len(user_running_tasks) >= user_type_details["max_user_tasks"]:
        await message.reply_text(
            f"❌ You have reached your limit of **{user_type_details['max_user_tasks']}** parallel recordings. Please wait for one to finish.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    try:
        command_args_text = (
            message.text.split(maxsplit=1)[1]
            if len(message.text.split()) > 1
            else ""
        )
        parsed_args = shlex.split(command_args_text)
        if len(parsed_args) < 2:
            raise ValueError("Not enough arguments")
        (input_identifier, timestamp_str) = (parsed_args[0], parsed_args[1])
        m3u8_list_specifier = next(
            (arg for arg in parsed_args if arg.lower().startswith(".l")), None
        )
        raw_filename = ""
        if len(parsed_args) > 2:
            start_index = 2
            end_index = len(parsed_args)
            if m3u8_list_specifier and parsed_args[-1] == m3u8_list_specifier:
                end_index -= 1
            raw_filename = " ".join(parsed_args[start_index:end_index])
        total_seconds = parse_duration(timestamp_str)
        if (
            total_seconds <= 0
            or total_seconds > user_type_details["max_duration_sec"]
        ):
            max_dur_str = (
                "Unlimited ♾️"
                if user_type_details["max_duration_sec"] == float("inf")
                else format_duration_hhmmss(int(user_type_details["max_duration_sec"]))
            )
            await message.reply_text(
                f"❌ <b>Invalid Duration.</b> Your limit is <code>{max_dur_str}</code>.",
                parse_mode=enums.ParseMode.HTML,
            )
            return
    except (ValueError, IndexError):
        await message.reply_text(
            '📝 <b>Usage:</b> <code>/rec "[URL/Channel]" [HH:MM:SS] [Filename] [.L#]</code>\n\n❌ **Error:** Invalid format or missing arguments.',
            parse_mode=enums.ParseMode.HTML,
        )
        return
    target_url = input_identifier
    if not target_url.startswith(("http://", "https://")):
        channel_details = get_channel_details_from_all_lists(
            input_identifier, m3u8_list_specifier
        )
        if not channel_details or not channel_details.get("url"):
            await message.reply(
                f"⚠️ Channel <code>{escape_html(input_identifier)}</code> not found.",
                parse_mode=enums.ParseMode.HTML,
            )
            return
        target_url = channel_details.get("url")
        if not raw_filename:
            raw_filename = channel_details.get("name", input_identifier)
    if not raw_filename:
        await message.reply_text(
            "❌ **Filename is required** for direct URLs.",
            parse_mode=enums.ParseMode.HTML,
        )
        return
    job_id = secrets.token_hex(4)
    job_dir = os.path.join(OUTPUT_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)
    final_filename = f"@QzbCast {sanitize_filename(raw_filename)}.mkv"
    final_output_path = os.path.join(job_dir, final_filename)
    chat_id = message.chat.id
    msg = await message.reply_text(
        f"🎬 **Job Created!**\nID: `{job_id}`\n\n🔍 Probing stream (Attempt 1/2)..."
    )
    info = None
    use_header = False
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffprobe",
            "-v",
            "error",
            "-show_streams",
            "-print_format",
            "json",
            target_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        (out, err) = await asyncio.wait_for(
            proc.communicate(), timeout=config.FFPROBE_TIMEOUT
        )
        if proc.returncode == 0:
            info = json.loads(out.decode())
        else:
            raise IOError(err.decode())
    except Exception as e:
        LOG.warning(
            f"Probe failed without headers for {target_url}: {e}. Retrying with headers."
        )
        await msg.edit_text(
            f"🎬 **Job Created!**\nID: `{job_id}`\n\n⚠️ Probe failed. Retrying with headers (Attempt 2/2)..."
        )
        try:
            parsed_url = urlparse(target_url)
            referer = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            headers_str = (
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 "
                "Safari/537.36\r\nReferer: " + referer + "\r\n"
            )
            proc_with_headers = await asyncio.create_subprocess_exec(
                "ffprobe",
                "-v",
                "error",
                "-headers",
                headers_str,
                "-show_streams",
                "-print_format",
                "json",
                target_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            (out, err) = await asyncio.wait_for(
                proc_with_headers.communicate(), timeout=config.FFPROBE_TIMEOUT
            )
            if proc_with_headers.returncode == 0:
                info = json.loads(out.decode())
                use_header = True
            else:
                raise IOError(err.decode())
        except Exception as final_e:
            LOG.error(f"Probe failed even with headers for {target_url}: {final_e}")
            await msg.edit_text(
                f"❌ Could not get stream info. The URL may be invalid, offline, or geo-blocked.\n\n`{final_e}`"
            )
            return
    if not info:
        await msg.edit_text(
            "❌ An unknown error occurred during stream probing."
        )
        return
    (videos, audios) = ([], [])
    for stream in info.get("streams", []):
        if stream.get("codec_type") == "video":
            videos.append(
                {
                    "index": stream["index"],
                    "width": stream.get("width", "N/A"),
                    "height": stream.get("height", "N/A"),
                }
            )
        elif stream.get("codec_type") == "audio":
            audios.append(
                {
                    "index": stream["index"],
                    "language": stream.get("tags", {}).get("language", "und"),
                }
            )
    if not videos:
        await msg.edit_text(
            "❌ No video tracks found in this stream! Cannot record."
        )
        return
    pending_states.setdefault(chat_id, {})[job_id] = {
        "msg_id": msg.id,
        "user_id": user_id,
        "original_message_id": message.id,
        "cancelled": False,
        "url": target_url,
        "duration": total_seconds,
        "filename": final_output_path,
        "videos": videos,
        "audios": audios,
        "selected_video": None,
        "selected_audios": [],
        "use_header": use_header,
        "status": "Initializing ⚙️",
    }
    buttons = [
        [
            InlineKeyboardButton(
                f"🎥 {v['width']}x{v['height']} (v{v['index']})",
                callback_data=f"vidsel_{user_id}_{job_id}_{v['index']}",
            )
        ]
        for v in videos
    ]
    buttons.append(
        [
            InlineKeyboardButton(
                "❌ Cancel Setup", callback_data=f"cancel_{user_id}_{job_id}"
            )
        ]
    )
    await msg.edit_text(
        f"**Select a Video Track for Job `{job_id}`:**",
        reply_markup=InlineKeyboardMarkup(buttons),
    )


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("showall_"))
)
@user_is_requester
async def show_all_channels_callback(bot, query):
    """Handles showing ALL channels in a list, with correct formatting."""
    try:
        (prefix, requester_id_str, list_name, page_str) = query.data.split("_", 3)
        page = int(page_str)
        requester_id = int(requester_id_str)
    except ValueError:
        await query.answer("Invalid button format.", show_alert=True)
        return
    all_list_names = sorted(load_m3u8_channels().keys())
    list_number = (
        all_list_names.index(list_name) + 1 if list_name in all_list_names else "N/A"
    )
    all_channels = sorted(
        load_m3u8_channels().get(list_name, {}).values(),
        key=lambda d: d.get("name", ""),
    )
    CHANNELS_PER_DETAILED_PAGE = 5
    total_pages = (
        len(all_channels) + CHANNELS_PER_DETAILED_PAGE - 1
    ) // CHANNELS_PER_DETAILED_PAGE
    paginated_channels = all_channels[
        page * CHANNELS_PER_DETAILED_PAGE : (page + 1) * CHANNELS_PER_DETAILED_PAGE
    ]
    channel_text_parts = [
        f"🔹 <b>Name:</b> <code>{escape_html(c.get('name', 'N/A'))}</code>\n🔹 <b>Group:</b> <code>{escape_html(c.get('Group', 'N/A'))}</code>"
        for c in paginated_channels
    ]
    channel_text = "\n----------------------------------\n".join(channel_text_parts)
    rows = []
    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                "⬅️",
                callback_data=f"showall_{requester_id}_{list_name}_{page - 1}",
            )
        )
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton(
                "➡️",
                callback_data=f"showall_{requester_id}_{list_name}_{page + 1}",
            )
        )
    if nav:
        rows.append(nav)
    rows.append(
        [
            InlineKeyboardButton(
                "🔙 Back to Groups",
                callback_data=f"showlist_{requester_id}_{list_name}_0",
            )
        ]
    )
    header = f"📦 All Channels in '{list_name}' [L{list_number}] (Page {page + 1}/{total_pages}):"
    await query.message.edit_text(
        f"{header}\n\n{channel_text}\n\n<i>(Menu for <code>{requester_id}</code>)</i>",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=enums.ParseMode.HTML,
    )
    await query.answer()


@dtbot.on_callback_query(
    filters.create(lambda _, __, q: q.data.startswith("backlists_"))
)
@user_is_requester
async def back_to_main_list_callback(bot, query):
    """Handles the 'Back to Lists' button."""

    class MockMessage:
        def __init__(self, user):
            self.from_user = user

        async def reply(self, text=None, reply_markup=None, parse_mode=None):
            await query.message.edit_text(
                text, reply_markup=reply_markup, parse_mode=parse_mode
            )

    await query.answer()
    await channel_cmd(bot, MockMessage(query.from_user))


async def main():
    """Main function to start the bot and workers."""
    num_workers = config.NUM_WORKERS
    workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
    LOG.info("🚀 Starting DoraToonz Recorder Bot...")
    os.makedirs(config.M3U8_FILES_DIRECTORY, exist_ok=True)
    await dtbot.start()
    LOG.info("Bot is now running and listening for commands.")
    await asyncio.gather(*workers)


if __name__ == "__main__":
    try:
        dtbot.run(main())
    except KeyboardInterrupt:
        LOG.info("Bot is shutting down.")
