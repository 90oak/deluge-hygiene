import os
from deluge_client import DelugeRPCClient  # ✅ Correct import

# Deluge connection settings
DELUGE_HOST = "127.0.0.1"
DELUGE_PORT = 58846
DELUGE_USER = "yourdelugeID"
DELUGE_PASS = "yourdelugepassword"

# Path to Deluge's download directory
DOWNLOAD_PATH = "/var/lib/deluged/Downloads"

def get_available_space(path):
    """Return available disk space in bytes."""
    statvfs = os.statvfs(path)
    return statvfs.f_bavail * statvfs.f_frsize  # Available blocks * block size

def main():
    # ✅ Create the DelugeRPCClient instance correctly
    client = DelugeRPCClient(DELUGE_HOST, DELUGE_PORT, DELUGE_USER, DELUGE_PASS)

    # ✅ Connect to Deluge
    client.connect()

    # ✅ Get all torrents
    torrents = client.call("core.get_torrents_status", {}, ["name", "total_size", "progress"])
    #Debug
    #print("Received data from Deluge:")
    #print(torrents)  # ✅ Add this to debug

    # ✅ Get available disk space
    available_space = get_available_space(DOWNLOAD_PATH)
    print(f"Available disk space: {available_space / (1024**3):.2f} GB")




    for torrent_id, data in torrents.items():
        torrent_id = torrent_id.decode("utf-8")  # Decode torrent ID
        data = {k.decode("utf-8"): v.decode("utf-8") if isinstance(v, bytes) else v for k, v in data.items()}  # Decode keys and values
    
        name = data["name"]  # Now this should work fine
        total_size = data["total_size"]
        progress = data["progress"]
        #debug
        print(f"Processing torrent: {torrent_id}")
        print(f"Data: {data}")  # ✅ Add this to inspect structure

        remaining_size = total_size * (1 - (progress / 100))

        print(f"Torrent: {name}, Size: {total_size / (1024**3):.2f} GB, Remaining: {remaining_size / (1024**3):.2f} GB")

        # ✅ Remove torrent if remaining download size > available space
        if remaining_size > available_space:
            print(f"🚨 Removing torrent: {name} (ID: {torrent_id}) - Not enough space!")
            client.call("core.remove_torrent", torrent_id, True)  # True = remove data

if __name__ == "__main__":
    main()
