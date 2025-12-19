# Pre-compiled Tools Directory

Place your pre-compiled .NET executables here, organized by framework version:

```
Tools/
├── net35/
│   ├── Rubeus.exe
│   ├── Seatbelt.exe
│   └── ...
├── net40/
│   ├── Rubeus.exe
│   ├── Seatbelt.exe
│   └── ...
└── net48/
    ├── Rubeus.exe
    ├── Seatbelt.exe
    └── ...
```

## Supported Tools

Any .NET executable can be loaded via the `Assembly` command or tool wrapper tasks.

## Usage

```
# Direct assembly execution
Assembly /tool:Rubeus.exe /args:"kerberoast /nowrap"

# Or via wrapper tasks (if configured)
Rubeus kerberoast /nowrap
Seatbelt -group=all
```

