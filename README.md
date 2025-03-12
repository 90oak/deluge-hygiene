# deluge-hygiene
Scripts to keep deluge server tidy

For sh script:

`apt install deluge-console`

For python script:

Check here for latest version: https://pypi.org/project/deluge-client/
Replace version number in URL with latest version from above.
```
wget https://files.pythonhosted.org/packages/source/d/deluge-client/deluge-client-1.9.0.tar.gz
wget https://pypi.io/packages/source/d/deluge-client/deluge-client-1.9.0.tar.gz
tar -xzf deluge-client-1.9.0.tar.gz
sudo cp -r deluge-client-1.9.0/deluge_client /usr/local/lib/python3.11/dist-packages/
python3 -c "import deluge_client; print(deluge_client.__file__)"
```
Verify output is `/usr/local/lib/python3.11/dist-packages/deluge_client/__init__.py`
```
rm -rf deluge-client-1.9.0 deluge-client-1.9.0.tar.gz
python3 remove_oversized_torrents.py
apt install cron
crontab -e
```
Add `0 * * * * /usr/bin/python3 /path/to/remove_oversized_torrents.py` at bottom of file to run script hourly, save, exit.
```
crontab -l
sudo systemctl status cron
```
