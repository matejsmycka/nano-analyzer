# Nano-analyzer

**A minimal LLM-powered zero-day vulnerability scanner by [AISLE](https://aisle.com).** Research prototype — scans source code for memory safety bugs using Claude Code as both orchestrator and analysis model, with multi-round skeptical triage.

```bash
git clone https://github.com/weareaisle/nano-analyzer.git && cd nano-analyzer
claude "/scan ./path/to/target"
```

## License

Apache License 2.0
