# Mariae Vault

A local Flask digital locker. Accounts and encrypted files are stored under `D:\School\MariaeVault\AdminVault` by default. Set `LOCKER_MOTHER_FOLDER` to use a different parent folder.

## Run locally

1. Use Python 3.10 or later and install dependencies with `python -m pip install -r requirements.txt`.
2. Start the app with `python app.py` and open `http://127.0.0.1:5000`.

The app creates `AdminVault` and one subfolder per account automatically. Folders created in the locker are also created as nested directories inside that account's directory, and encrypted files are stored in their selected folder. Each account has a 100 MB encrypted-storage quota with no separate per-file cap; the app displays current usage. Each file is encrypted with 3DES-CBC and an HMAC-SHA256 integrity tag before it is written. SQLite stores account credentials as salted PBKDF2-HMAC-SHA256 hashes and keeps the file and folder index. Upload into the current folder, and move or copy files between folders. Preview opens supported content in the browser; downloads restore the original filename. Existing files are placed in the account root during migration. New passwords must be at least 8 characters.

The first run creates an administrator account with username `Admin` and the temporary password `Admin2627`. The administrator console is available at `/admin` after login. Recovery codes are generated for an administrator to share with a user out of band and expire after one hour. Backup archives contain the account database and encrypted files; store them securely.

## Use from another PC on the same network

Run the Flask app on the PC that owns the database, then open the app from the other PC's browser. In PowerShell on the server PC, set the network bind and start the app:

```powershell
$env:LOCKER_HOST = "0.0.0.0"
python app.py
```

Find the server PC's IPv4 address with `ipconfig`, then visit `http://SERVER-IP:5000` from the other PC (for example, `http://192.168.1.25:5000`). Allow inbound TCP port 5000 through Windows Firewall for the Private network if Windows prompts. Keep both PCs on a trusted network.

To store encrypted account folders on a shared folder hosted by a different PC, share a dedicated folder there and grant the Windows account running this app read/write access. On the server PC, set `LOCKER_MOTHER_FOLDER` to that share's UNC path before starting the app, for example:

```powershell
$env:LOCKER_MOTHER_FOLDER = "\\FILE-PC\MariaeVaultShare"
$env:LOCKER_HOST = "0.0.0.0"
python app.py
```

Use the UNC path (`\\FILE-PC\ShareName`), not a mapped drive letter, because Windows services and elevated processes may not see mapped drives. `locker.db` remains local beside `app.py`; do not place SQLite on the network share. Only one running app instance should use this database and shared storage at a time. The share must be reachable and writable before app startup. Set these environment variables again in each PowerShell window, or configure them persistently in Windows before starting the app.

DSA creates digital signatures and cannot encrypt credentials, so login uses salted password hashes. 3DES is a legacy cipher retained because it was requested; AES-GCM is a better choice for a production locker.
