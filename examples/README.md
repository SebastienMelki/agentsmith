# Examples

Each subdirectory is a self-contained, ready-to-copy agentsmith setup. Pick one
that matches your topology, copy both files into the repo root, and fill in
`agentsmith.env`:

```bash
cp examples/<name>/config.yaml   config.yaml
cp examples/<name>/.env.example  agentsmith.env
$EDITOR agentsmith.env           # paste real values
make run
```

| Example | Backends | When to use it |
|---|---|---|
| [`single-backend/`](single-backend/) | One generic MCP server with bearer-token auth | Smallest possible setup; good starting template when adapting to a new backend |
| [`dodo-and-slack/`](dodo-and-slack/) | [Dodo Payments](https://dodopayments.com) + Slack | Real two-backend federation; demonstrates per-backend header isolation across vendors |

## Adding a new example

Follow the existing shape so the README table and quickstart instructions
keep working:

```
examples/<your-backend>/
├── .env.example   # one line per ${VAR} in config.yaml, with placeholder values
└── config.yaml    # references ${VAR} for every secret; opens with a comment block
```

The leading comment block in `config.yaml` should explain (a) what the
backend is, (b) what tools it exposes after namespacing, and (c) the copy
steps to run it. See `dodo-and-slack/config.yaml` for a model.
