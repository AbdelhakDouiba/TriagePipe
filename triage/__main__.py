"""
Point d'entrée simple pour tester le triage en local.

Usage :
    python -m triage <chemin_projet> [rapport.json]

Le rapport peut etre Bandit (cle 'results') ou GitLeaks (liste / 'findings').
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .file_scanner import collect_project_files, find_unused_files
from .sast_filter import triage_bandit_report, triage_sast_alerts
from .secrets_filter import triage_gitleaks_report, triage_secret_alerts


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("Usage: python -m triage <chemin_projet> [rapport.json]")
        return 1

    project_root = Path(args[0]).resolve()
    test_files, productive_files = collect_project_files(project_root)
    unused = find_unused_files(project_root, productive_files)

    print(f"Projet : {project_root}")
    print(f"  Fichiers de test      : {len(test_files)}")
    for f in test_files:
        print(f"    [TEST] {f.relative_to(project_root)}")
    print(f"  Fichiers productifs   : {len(productive_files)}")
    for f in productive_files:
        print(f"    [PROD] {f.relative_to(project_root)}")
    print(f"  Fichiers non utilises : {len(unused)}")
    for f in unused:
        print(f"    [UNUSED] {f.relative_to(project_root)}")

    if len(args) >= 2:
        report_path = Path(args[1])
        data = json.loads(report_path.read_text(encoding="utf-8"))

        # Bandit
        if isinstance(data, dict) and "results" in data:
            triaged = triage_bandit_report(data, project_root)
            print("\nResume triage Bandit :")
            print(f"  {triaged['triage']}")
            for alert in triaged["results"]:
                print(
                    f"  - {alert.get('filename')}: "
                    f"confiance {alert.get('confiance_originale')} -> "
                    f"{alert.get('confiance_ajustee')} | "
                    f"{alert.get('raison_déprioritisation')}"
                )
        # GitLeaks (liste de findings ou dict avec findings/leaks)
        elif isinstance(data, list) or (
            isinstance(data, dict)
            and any(k in data for k in ("findings", "leaks"))
        ):
            triaged = triage_gitleaks_report(data)
            print("\nResume triage GitLeaks :")
            print(f"  {triaged['triage']}")
            for alert in triaged["findings"]:
                secret = (alert.get("Secret") or "")[:16]
                print(
                    f"  - {secret}... : "
                    f"entropie={alert.get('entropie')} "
                    f"confiance {alert.get('confiance_originale')} -> "
                    f"{alert.get('confiance_ajustee')} | "
                    f"{alert.get('raison_déprioritisation')}"
                )
        else:
            results = triage_sast_alerts(
                data if isinstance(data, list) else [data], project_root
            )
            for alert in results:
                print(alert.get("raison_déprioritisation"))
            triaged = {"results": results}

        out = report_path.with_name(report_path.stem + "_triaged.json")
        out.write_text(
            json.dumps(triaged, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nRapport enrichi ecrit dans : {out}")
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
