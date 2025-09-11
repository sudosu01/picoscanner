import os, json

def file_to_text(path):
    try:
        return open(path, "r", encoding="utf-8", errors="ignore").read()
    except:
        return ""

def build_corpus(decompile_dir):
    corpus = {}
    for root, _, files in os.walk(decompile_dir):
        for fn in files:
            if fn.endswith((".smali", ".xml", ".java", ".txt")) or fn == "AndroidManifest.xml":
                fp = os.path.join(root, fn)
                corpus[fp] = file_to_text(fp)
    return corpus

def scan(decompile_dir, pico_db_path="pico_meta_db.json"):
    with open(pico_db_path, "r", encoding="utf-8") as f:
        PICO_DB = json.load(f)

    corpus = build_corpus(decompile_dir)
    results = []

    for sdk, conf in PICO_DB.items():
        sdk_result = {
            "SDK": sdk,
            "Found_Inits": [],
            "Found_Privacy_APIs": [],
            "Missing_Privacy_APIs": [],
            "PVPs": []
        }

        # Check init
        for init in conf.get("init", []):
            token = init if isinstance(init, str) else str(init)
            if any(token in txt for txt in corpus.values()):
                sdk_result["Found_Inits"].append(token)

        # Check privacy APIs by law
        for law in ("gdpr", "us_p", "coppa"):
            for api in conf.get(law, []):
                token = api if isinstance(api, str) else str(api)
                if token and any(token in txt for txt in corpus.values()):
                    sdk_result["Found_Privacy_APIs"].append(f"{law}:{token}")
                else:
                    sdk_result["Missing_Privacy_APIs"].append(f"{law}:{token}")
                    if token:
                        sdk_result["PVPs"].append("PVP #1")

        results.append(sdk_result)
    return results

def print_results(results):
    from tabulate import tabulate
    headers = ["SDK", "Found_Inits", "Found_Privacy_APIs", "Missing_Privacy_APIs", "PVPs"]
    table = [[
        r["SDK"],
        ", ".join(r["Found_Inits"]) or "-",
        ", ".join(r["Found_Privacy_APIs"]) or "-",
        ", ".join(r["Missing_Privacy_APIs"]) or "-",
        ", ".join(r["PVPs"]) or "-"
    ] for r in results]
    print(tabulate(table, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    path = input("Enter path to decompiled APK folder: ").strip()
    if not os.path.isdir(path):
        print("Invalid path, please check.")
    else:
        report = scan(path)
        print_results(report)
