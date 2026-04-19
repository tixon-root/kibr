import asyncio
from bot import flask_app, application

# Initialize the telegram application on startup
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.run_until_complete(application.initialize())

# Export flask_app for gunicorn
__all__ = ["flask_app"]
