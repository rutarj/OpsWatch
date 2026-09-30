"""Command-line interface: `opswatch <command>`. Run `opswatch -h` for the list."""
import argparse
import json
import sys

from opswatch.config import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opswatch", description="AI-assisted service desk with approval gates")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="generate the labeled dataset and knowledge base")
    sub.add_parser("train", help="train the ML baseline on the training split")
    ev = sub.add_parser("eval", help="evaluate triagers on the held-out test set")
    ev.add_argument("--triagers", default="rules,ml,llm,hybrid")
    ev.add_argument("--llm-limit", type=int, default=60, help="max tickets sent to the LLM (cost control)")
    ev.add_argument("--gate", action="store_true", help="exit non-zero if results drop below config/eval_gate.toml")
    sub.add_parser("demo", help="scripted end-to-end walkthrough (in memory, no API key)")
    sub.add_parser("serve-mcp", help="run the MCP server over stdio")
    api = sub.add_parser("serve-api", help="run the REST API and approval console")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8000)
    sub.add_parser("pending", help="list proposals waiting for approval")
    ap = sub.add_parser("approve", help="approve a proposal")
    ap.add_argument("action_id", type=int)
    ap.add_argument("--by", required=True)
    rj = sub.add_parser("reject", help="reject a proposal")
    rj.add_argument("action_id", type=int)
    rj.add_argument("--by", required=True)
    rj.add_argument("--reason", required=True)
    sub.add_parser("audit-verify", help="check the audit hash chain")
    args = parser.parse_args(argv)
    settings = get_settings()

    if args.cmd == "seed":
        from opswatch.seed import generate
        print(generate(settings.data_dir))
    elif args.cmd == "train":
        from opswatch.seed import generate, load_jsonl
        from opswatch.triage.ml import MLTriager
        if not (settings.data_dir / "tickets_train.jsonl").exists():
            generate(settings.data_dir)
        print("saved", MLTriager.train(load_jsonl(settings.data_dir / "tickets_train.jsonl")).save(settings.models_dir))
    elif args.cmd == "eval":
        from opswatch.config import PROJECT_ROOT
        from opswatch.evaluation.run import check_gate, run, write_reports
        results = run(settings, [t.strip() for t in args.triagers.split(",") if t.strip()], args.llm_limit)
        print("report:", write_reports(results, settings.reports_dir))
        for name, m in results["triagers"].items():
            print(f"  {name}: " + (m["skipped"] if "skipped" in m else
                                   f"category {m['category_accuracy_pct']}%, priority {m['priority_accuracy_pct']}%"))
        if args.gate:
            failures = check_gate(results, PROJECT_ROOT / "config" / "eval_gate.toml")
            for f in failures:
                print("GATE FAILED:", f)
            return 1 if failures else 0
    elif args.cmd == "demo":
        from opswatch.demo import run_demo
        run_demo()
    elif args.cmd == "serve-mcp":
        from opswatch.mcp_server import main as mcp_main
        mcp_main()
    elif args.cmd == "serve-api":
        import uvicorn

        from opswatch.api import build_default_app
        uvicorn.run(build_default_app(), host=args.host, port=args.port)
    else:
        from opswatch import audit
        from opswatch.actions import ActionError
        from opswatch.app import OpsWatch
        ops = OpsWatch.create(settings, triager_name="rules")
        try:
            if args.cmd == "pending":
                for a in ops.store.list_actions(status="pending"):
                    print(f"#{a['id']} {a['action']} on {a['ticket_id']} [{a['risk']}] by {a['proposed_by']}: "
                          f"{a['rationale']}")
            elif args.cmd == "approve":
                print(json.dumps(ops.approve(args.action_id, args.by), indent=2))
            elif args.cmd == "reject":
                print(json.dumps(ops.reject(args.action_id, args.by, args.reason), indent=2))
            elif args.cmd == "audit-verify":
                result = audit.verify(ops.store.conn)
                print(result)
                return 0 if result["ok"] else 1
        except ActionError as exc:
            print("refused:", exc, file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
