#!/bin/bash

# Set the path to your Deluge download directory
DOWNLOAD_PATH="/var/lib/deluged/Downloads"

# Deluge authentication credentials
DELUGE_USER="yourdelugeuserID"
DELUGE_PASS="yourdelugepassword"

# Get available disk space in bytes
AVAILABLE_SPACE=$(df --output=avail "$DOWNLOAD_PATH" | tail -n 1)
AVAILABLE_SPACE=$((AVAILABLE_SPACE * 1024))  # Convert KB to bytes

# Get torrent details for downloading torrents
deluge-console "connect 127.0.0.1:58846 $DELUGE_USER $DELUGE_PASS; info -v" | awk -v avail_space="$AVAILABLE_SPACE" '
    BEGIN { torrent_id=""; total_size=0; downloaded_size=0 }
    /^ID:/ { torrent_id=$2 }
    /^State: Downloading/ { downloading=1 }
    /^Size:/ {
        if ($3 ~ /\//) {
            split($3, sizes, "/");
            downloaded_size = sizes[1];  # Extract downloaded amount
            total_size = sizes[2];       # Extract total torrent size
        }
    }
    # After processing all fields for a torrent, check conditions
    /^Download Folder:/ {
        if (downloading && total_size > 0) {
            # Convert sizes to bytes
            downloaded_size_bytes = downloaded_size * 1024 * 1024 * 1024;
            total_size_bytes = total_size * 1024 * 1024 * 1024;
            remaining_size = total_size_bytes - downloaded_size_bytes;

            # Check if remaining download exceeds available space
            if (remaining_size > avail_space) {
                print torrent_id;
            }
        }
        downloading=0; total_size=0; downloaded_size=0;
    }
' | while read -r torrent_id; do
    echo "Removing torrent: $torrent_id (Not enough disk space)"
    deluge-console "connect 127.0.0.1:58846 $DELUGE_USER $DELUGE_PASS; del --remove_data -c $torrent_id"
done
