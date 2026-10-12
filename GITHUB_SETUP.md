# Open in VS Code and upload to GitHub

Extract this archive and open the team-edr folder in VS Code.
The agent runs on Linux; Windows can edit the source and run the synthetic demo with Python installed.

## Windows demo (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe agent.py --demo
.\.venv\Scripts\python.exe dashboard.py --database runs/demo.db
```

Open http://127.0.0.1:8080. This demo is synthetic, not live attack evidence.

## Ubuntu live lab

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo .venv/bin/python agent.py --config config.json
```

Install tshark and python3-venv through apt if missing. In a separate terminal:

```bash
sudo .venv/bin/python dashboard.py --database runs/live.db
```

The config uses ens33, Juice Shop 192.168.100.100:3000 and notification-only response.
Teammates must change their interface/IP settings to match their own lab.

## GitHub

Use VS Code Source Control > Initialize Repository, review staged files, commit,
then Publish to GitHub and choose a private repository initially.
Do not upload .venv, databases, credentials or captured traffic.
Choose a project licence with your team before making the repository public.
VM-only results and later VM edits are not included in this source archive.
