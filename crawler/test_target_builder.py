import json
import os

from .target_builder import build_target_pool, save_target_pool


def main():
    input_path = "results/crawl_output.json"
    output_path = "results/targets.json"

    with open(input_path, "r", encoding="utf-8") as f:
        crawl_data = json.load(f)

    targets = build_target_pool(crawl_data)

    os.makedirs("results", exist_ok=True)
    save_target_pool(targets, output_path)

    print(f"[+] Generated {len(targets)} targets")
    print(f"[+] Saved to {output_path}")

    for item in targets:
        print(item)


if __name__ == "__main__":
    main()
