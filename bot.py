import os
from datetime import datetime, timezone

import discord
from discord import app_commands
from discord.ext import commands

from db import get_conn, init_db, create_license


DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
ADMIN_DISCORD_IDS = {
    int(x.strip())
    for x in os.getenv("ADMIN_DISCORD_IDS", "").split(",")
    if x.strip().isdigit()
}


def is_admin(interaction: discord.Interaction):
    return interaction.user.id in ADMIN_DISCORD_IDS


intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)


def ensure_online_columns():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;")
            cur.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS online BOOLEAN NOT NULL DEFAULT FALSE;")
        conn.commit()


@bot.event
async def on_ready():
    init_db()
    ensure_online_columns()
    await bot.tree.sync()
    print(f"Logged in as {bot.user}")


@bot.tree.command(name="generate", description="Generate a new license key")
@app_commands.describe(days="How many days the key should last", note="Optional note")
async def generate(interaction: discord.Interaction, days: int = 30, note: str = ""):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    lic = create_license(days=days, note=note or None)

    await interaction.response.send_message(
        f"✅ Key generated:\n```{lic['license_key']}```\nExpires: `{lic['expires_at']}`",
        ephemeral=True
    )


@bot.tree.command(name="ban", description="Ban a license key")
async def ban(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET banned = TRUE, active = FALSE, online = FALSE
                WHERE license_key = %s
                RETURNING license_key;
            """, (key,))
            row = cur.fetchone()
        conn.commit()

    await interaction.response.send_message("✅ Key banned." if row else "❌ Key not found.", ephemeral=True)


@bot.tree.command(name="remove", description="Delete a license key")
async def remove(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM licenses WHERE license_key = %s RETURNING license_key;", (key,))
            row = cur.fetchone()
        conn.commit()

    await interaction.response.send_message("✅ Key removed." if row else "❌ Key not found.", ephemeral=True)


@bot.tree.command(name="resetpc", description="Reset the PC lock on a key")
async def resetpc(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET hwid = NULL, online = FALSE
                WHERE license_key = %s
                RETURNING license_key;
            """, (key,))
            row = cur.fetchone()
        conn.commit()

    await interaction.response.send_message("✅ PC lock reset." if row else "❌ Key not found.", ephemeral=True)


@bot.tree.command(name="info", description="View license info")
async def info(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    ensure_online_columns()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key = %s;", (key,))
            row = cur.fetchone()

    if not row:
        await interaction.response.send_message("❌ Key not found.", ephemeral=True)
        return

    await interaction.response.send_message(
        f"""
**Key:** `{row['license_key']}`
**Active:** `{row['active']}`
**Banned:** `{row['banned']}`
**Online:** `{row.get('online')}`
**HWID:** `{row['hwid']}`
**Expires:** `{row['expires_at']}`
**Last Seen:** `{row.get('last_seen_at')}`
**Note:** `{row['note']}`
""",
        ephemeral=True
    )


@bot.tree.command(name="online", description="Show users currently online")
async def online(interaction: discord.Interaction):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    ensure_online_columns()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET online = FALSE
                WHERE last_seen_at IS NULL OR last_seen_at < NOW() - INTERVAL '2 minutes';
            """)

            cur.execute("""
                SELECT license_key, hwid, expires_at, last_seen_at, note
                FROM licenses
                WHERE online = TRUE
                  AND last_seen_at >= NOW() - INTERVAL '2 minutes'
                ORDER BY last_seen_at DESC;
            """)
            rows = cur.fetchall()

        conn.commit()

    if not rows:
        await interaction.response.send_message("No users online.", ephemeral=True)
        return

    msg = "**Online users:**\n\n"

    for row in rows[:15]:
        hwid_short = row["hwid"][:16] + "..." if row["hwid"] else "None"
        msg += (
            f"🟢 `{row['license_key']}`\n"
            f"HWID: `{hwid_short}`\n"
            f"Last Seen: `{row['last_seen_at']}`\n"
            f"Expires: `{row['expires_at']}`\n"
            f"Note: `{row['note']}`\n\n"
        )

    await interaction.response.send_message(msg, ephemeral=True)


if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing")

bot.run(DISCORD_TOKEN)
