import os
import sys
from pathlib import Path


def fix_double_utf8(text):
    """   UTF-8 ->  UTF-8"""
    #      
    if 'С' in text or 'П' in text or ' ' in text:
        try:
            # :  UTF-8 ->  UTF-8
            return text.encode('cp1251', errors='ignore').decode('utf-8', errors='ignore')
        except:
            return text
    return text


def process_file(filepath):
    """  """
    try:
        #     
        with open(filepath, 'rb') as f:
            raw_data = f.read()

        #   
        encodings_to_try = ['utf-8', 'cp1251', 'iso-8859-5', 'cp866']

        for encoding in encodings_to_try:
            try:
                text = raw_data.decode(encoding)
                #      
                if encoding == 'utf-8' and ('С' in text or 'П' in text):
                    text = fix_double_utf8(text)

                #    UTF-8
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(text)

                print(f" {filepath} -  (: {encoding})")
                return True

            except UnicodeDecodeError:
                continue

        print(f" {filepath} -    ")
        return False

    except Exception as e:
        print(f" {filepath} - : {e}")
        return False


def main():
    print("   ...")
    print("=" * 50)

    #   Python   README
    processed = 0
    failed = 0

    for filepath in Path('.').rglob('*.py'):
        #   
        if '.venv' in str(filepath):
            continue
        if '.git' in str(filepath):
            continue

        if process_file(filepath):
            processed += 1
        else:
            failed += 1

    #   README.md  
    readme_files = ['README.md', 'README.txt', 'readme.md']
    for readme in readme_files:
        if os.path.exists(readme):
            if process_file(readme):
                processed += 1
            else:
                failed += 1

    print("=" * 50)
    print(f"! : {processed},  : {failed}")

    if failed == 0:
        print("\n   :")
        print("git add .")
        print('git commit -m "Fix:    "')
        print("git push")
    else:
        print("\n    .")
        print("    PyCharm     UTF-8.")


if __name__ == "__main__":
    main()