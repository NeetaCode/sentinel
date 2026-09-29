import argparse
import asyncio
import json

from . import detector, gen_logs, pipeline, store


def main():
    ap = argparse.ArgumentParser(prog="sentinel")
    ap.add_argument("cmd", choices=["gen", "train", "triage", "list", "approve", "reject", "audit"])
    ap.add_argument("id", nargs="?", type=int)
    ap.add_argument("--by", default="analyst")
    a = ap.parse_args()
    if a.cmd == "gen":
        print("rows:", gen_logs.generate())
    elif a.cmd == "train":
        print(json.dumps(detector.train()))
    elif a.cmd == "triage":
        for r in asyncio.run(pipeline.run_triage()):
            print(r)
    elif a.cmd == "list":
        for r in store.list_():
            print(r["id"], r["status"].upper(), r["action"], r["target"], f'{r["confidence"]:.2f}', "|", r["note"], "|", r["reasoning"][:90])
    elif a.cmd in ("approve", "reject"):
        print(pipeline.decide(a.id, a.by, a.cmd == "approve"))
    elif a.cmd == "audit":
        for r in store.audit():
            print(r)

if __name__ == "__main__":
    main()
