import argparse
from audit_agent import AuditAgent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--audit", type=str)
    parser.add_argument("--sniper", action="store_true")
    args = parser.parse_args()

    agent = AuditAgent()
    if args.build:
        agent.build_db(count=args.count)
    elif args.audit:
        agent.audit(args.audit, sniper=args.sniper)

if __name__ == "__main__":
    main()