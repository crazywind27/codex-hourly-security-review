# GitHub Upload Notes

This folder is the GitHub-safe package. It intentionally does not include local
configuration, generated run evidence, event logs, state files, or action logs.

## Web Upload

1. Create a new GitHub repository.
2. Upload the files from this folder.
3. Do not upload `config.json`, `runs/`, `state.json`, or generated logs.

## Git CLI Upload

Run these commands from this folder on a machine with Git installed:

```powershell
git init
git add .
git commit -m "Initial Codex hourly security review package"
git branch -M main
git remote add origin https://github.com/YOUR_USER/YOUR_REPO.git
git push -u origin main
```

For a private repo, create the GitHub repository as private before pushing.

## After Clone

Each installed machine should create its own local `config.json` from
`config.example.json`. Do not commit that file.
