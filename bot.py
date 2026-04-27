import os
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


@bot.event
async def on_ready():
    init_db()
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
                SET banned = TRUE, active = FALSE
                WHERE license_key = %s
                RETURNING license_key;
            """, (key,))
            row = cur.fetchone()
        conn.commit()

    await interaction.response.send_message(
        "✅ Key banned." if row else "❌ Key not found.",
        ephemeral=True
    )


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

    await interaction.response.send_message(
        "✅ Key removed." if row else "❌ Key not found.",
        ephemeral=True
    )


@bot.tree.command(name="resetpc", description="Reset the PC lock on a key")
async def resetpc(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE licenses
                SET hwid = NULL
                WHERE license_key = %s
                RETURNING license_key;
            """, (key,))
            row = cur.fetchone()
        conn.commit()

    await interaction.response.send_message(
        "✅ PC lock reset." if row else "❌ Key not found.",
        ephemeral=True
    )


@bot.tree.command(name="info", description="View license info")
async def info(interaction: discord.Interaction, key: str):
    if not is_admin(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return

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
**HWID:** `{row['hwid']}`
**Expires:** `{row['expires_at']}`
**Note:** `{row['note']}`
""",
        ephemeral=True
    )


if not DISCORD_TOKEN:
    raise RuntimeError("DISCORD_TOKEN is missing")

bot.run(DISCORD_TOKEN)