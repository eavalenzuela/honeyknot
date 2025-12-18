# honeyknot
a multi-port http honeypot for farming malware

## Service schema
Services can now be defined in a single JSON or YAML schema file (default: `definition_files/services.json`). Each entry describes the protocol (`http` or `tcp`), listener settings, headers, and regex-based response rules. Provide a different schema at runtime with `--service_schema <path>`.

To migrate legacy `handlers/` INI files into the consolidated format, run:

```
python service_loader.py --from-handlers handlers --definition-dir definition_files --output definition_files/services.migrated.json
```

You can also export during startup with `--export_schema <path>`, which writes the schema and exits.
