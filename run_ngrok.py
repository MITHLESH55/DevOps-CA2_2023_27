"""
Launch Flask app + ngrok tunnel for public access.
"""
import threading
import time
import sys
import os

# Fix Windows console encoding
os.environ["PYTHONIOENCODING"] = "utf-8"

def start_flask():
    from web.app import app
    app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)

def start_ngrok():
    from pyngrok import ngrok

    # Small delay to let Flask start
    time.sleep(2)

    try:
        tunnel = ngrok.connect(5000, "http")
        public_url = tunnel.public_url

        print()
        print("=" * 62)
        print("  SECURE FILE TRANSFER SYSTEM -- LIVE ON NGROK")
        print("=" * 62)
        print()
        print(f"  PUBLIC URL:  {public_url}")
        print()
        print(f"  Receiver page:  {public_url}/receiver")
        print(f"  Sender page:    {public_url}/sender")
        print()
        print("  Share the PUBLIC URL with anyone to access the app!")
        print()
        print("=" * 62)
        print("  Press Ctrl+C to stop.")
        print("=" * 62)
        print()

    except Exception as e:
        print(f"\nNgrok error: {e}")
        print("\nIf you need an auth token, run:")
        print("  ngrok config add-authtoken YOUR_TOKEN")
        print("\nGet a free token at: https://dashboard.ngrok.com/get-started/your-authtoken")
        sys.exit(1)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # Run ngrok in main thread so Ctrl+C works
    start_ngrok()

    # Keep alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
