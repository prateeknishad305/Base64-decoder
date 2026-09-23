# Example configuration for recovered_bot.py
# Copy this file to `config.py` and fill in real values.
# NOTE: All values below are placeholders. Never commit real secrets.

# --- Telegram / Pyrogram ---
API_ID = 0
API_HASH = "your-api-hash"
BOT_TOKEN = "your-bot-token"

# Telegram user id of the bot owner (super-admin). Integer.
OWNER_ID = 0

# Chat/group id used as the official working group.
WORKING_GROUP = 0

# Public invite link shown to users in access-denied messages.
GROUP_LINK = "https://t.me/your_official_group"

# --- Database ---
MONGO_URI = "mongodb://localhost:27017"

# --- Files / paths ---
# Directory where uploaded M3U8 JSON files are stored.
M3U8_FILES_DIRECTORY = "m3u8_files"

# --- Recording / FFmpeg ---
# Seconds to wait for ffprobe before giving up.
FFPROBE_TIMEOUT = 60

# Minimum seconds between progress-message edits.
PROGRESS_UPDATE_INTERVAL = 10

# Number of concurrent worker coroutines.
NUM_WORKERS = 2

# Max number of jobs that may run in parallel globally.
GLOBAL_MAX_PARALLEL_TASKS = 4

# --- Tiers / limits ---
# Max recording duration (seconds) for premium users.
PREMIUM_MAX_DURATION_SEC = 0

# Max concurrent tasks for premium users.
PREMIUM_PARALLEL_TASKS = 4

# Max recording duration (seconds) for verified users.
VERIFIED_MAX_DURATION_SEC = 0

# Max concurrent tasks for verified users.
VERIFIED_PARALLEL_TASKS = 2

# Display timezone (pytz name).
TIMEZONE = "Asia/Kolkata"

# --- Verification / shortlink ---
# Enable the shortlink-based verification flow.
ENABLE_SHORTLINK = False

# Shortlink provider base URL and API key.
SHORTLINK_URL = ""
SHORTLINK_API = ""

# Verification validity window in seconds (shown as N hours).
VERIFICATION_EXPIRY_SECONDS = 86400

# --- UI ---
# Number of tasks shown per page in the /status listing.
STATUS_PAGE_SIZE = 5
