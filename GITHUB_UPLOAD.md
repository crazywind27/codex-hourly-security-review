# GitHub Upload Notes

This folder is the GitHub-safe package. It intentionally does not include local
configuration, generated run evidence, event logs, state files, alert
decisions, or action logs.

## Web Upload

1. Create a new GitHub repository.
2. Upload the files from this folder.
3. Do not upload `config.json`, `runs/`, `state.json`,
   `alert-decisions.json`, or generated logs.

For this package, the files that should be uploaded are the repository files in
this folder only, not the active installation directory and not the generated
zip archive.

## Git CLI Upload

Run these commands from this folder on a machine with Git installed:

```powershell
git init
git add .
git commit -m "Add alert disposition suppression tracking"
git branch -M main
git remote add origin https://github.com/YOUR_USER/YOUR_REPO.git
git push -u origin main
```

For a private repo, create the GitHub repository as private before pushing.

If you already have a working tree, copy these package files into that working
tree, then use the same `git add`, `commit`, and `push` steps there.

## After Clone

Each installed machine should create its own local `config.json` from
`config.example.json`. Do not commit that file.

On a new workstation, confirm Windows PowerShell can run local scripts before
installing the scheduled task. If the repo was downloaded as a ZIP, unblock the
PowerShell scripts first so `RemoteSigned` policy does not block them.
