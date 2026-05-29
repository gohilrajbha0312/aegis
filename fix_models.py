import os
import glob

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    original_content = content
    
    # Replace the direct gemini string
    if "'google:gemini-2.5-flash'" in content or '"google:gemini-2.5-flash"' in content:
        # Add import if missing
        if "from aegisx.core.models import default_model" not in content:
            content = "from aegisx.core.models import default_model\n" + content
            
        content = content.replace("'google:gemini-2.5-flash'", "default_model")
        content = content.replace('"google:gemini-2.5-flash"', "default_model")

    # Remove GEMINI_API_KEY checks in files like semantic_discovery.py
    lines = content.split('\n')
    new_lines = []
    skip = False
    for i, line in enumerate(lines):
        if 'if k == \'GEMINI_API_KEY\':' in line or 'if k == "GEMINI_API_KEY":' in line:
            new_lines.append(line.replace('GEMINI_API_KEY', 'OPENROUTER_API_KEY_2').replace('GOOGLE_API_KEY', 'OPENROUTER_API_KEY_2'))
        elif "GEMINI_API_KEY" in line and "os.environ" in line:
            new_lines.append(line.replace('GEMINI_API_KEY', 'OPENROUTER_API_KEY_2'))
        else:
            new_lines.append(line)

    content = '\n'.join(new_lines)
    
    # Specific fixes for aegisx.core.agents.advisor and reasoning which use raw google-genai
    if "GEMINI_API_KEY" in content:
        content = content.replace("GEMINI_API_KEY", "OPENROUTER_API_KEY_2")
        content = content.replace("'gemini-2.5-flash'", "default_model")
        content = content.replace('"gemini-2.5-flash"', "default_model")
        if "from aegisx.core.models import default_model" not in content:
             content = "from aegisx.core.models import default_model\n" + content

    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed {filepath}")

def main():
    search_dirs = [
        "/home/kali/Projects/aegisx/src/aegisx/agents/*.py",
        "/home/kali/Projects/aegisx/src/aegisx/core/agents/*.py"
    ]
    
    for d in search_dirs:
        for file in glob.glob(d):
            fix_file(file)

if __name__ == "__main__":
    main()
