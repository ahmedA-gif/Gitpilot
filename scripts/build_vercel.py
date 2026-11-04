"""Promote the Vite frontend to Vercel's static CDN output."""
from pathlib import Path
from shutil import copytree
copytree(Path('frontend/dist'), Path('public'), dirs_exist_ok=True)
