# Patchi Language Support Matrix

## Supported Languages (22)

| Language | Tree-Sitter | Scanner | Import Graph | Type Checker | Route Detection | Blast Radius | Fix Agents | Security Agents |
|----------|:-----------:|:-------:|:------------:|:------------:|:---------------:|:------------:|:----------:|:---------------:|
| Python | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| JavaScript | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| TypeScript | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Rust | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Java | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Go | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| C# | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kotlin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Swift | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ruby | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| PHP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Dart | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ | ✓ |
| C | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| C++ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| Svelte | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| Bash | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | ✓ |
| CSS | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ |
| SQL | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ |
| HTML | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ |
| JSON | — | stdlib | — | — | — | ✓ | — | ✓ |
| YAML | — | stdlib | — | — | — | ✓ | — | ✓ |
| Scala | — | regex | ✓ | — | — | ✓ | ✓ | ✓ |

### Key

- **✓** = Full support (tree-sitter AST)
- **stdlib** = Supported via standard library parser (JSON, YAML)
- **regex** = Regex/stdlib fallback (Scala: no PyPI tree-sitter grammar)
- **—** = Not applicable or not yet implemented

## Capability Details

### Scanner (imports, functions, classes, exports)
All 20 languages extract structured data via tree-sitter AST or stdlib parsers.

### Import Graph
Multi-language import resolution with 5 strategies: relative paths, path-style, Rust `::`, dotted modules, bare name fallback. Covers 30+ file extensions.

### Type Checker
AST-based type analysis for 10 languages: Python, TypeScript, JavaScript, Java, Go, Rust, C#, Kotlin, Swift, PHP, Dart.

### Route Detection
Framework-specific route/endpoint detection:
- **Python**: FastAPI, Flask, Django
- **JavaScript/TypeScript**: Express, Fastify, Next.js
- **Java**: Spring Boot
- **Go**: Gin, Echo, Fiber
- **Rust**: Actix, Axum, Rocket
- **Ruby**: Rails, Sinatra, Grape
- **PHP**: Laravel
- **C#**: ASP.NET Core
- **Kotlin**: Ktor
- **Swift**: Vapor

### Blast Radius
File-level and symbol-level blast radius via `ImportGraph` + `SymbolGraph`. Works for all languages in the import graph.

### Fix Agents
Multi-language code fixes, dependency updates, dead code removal, type fixes.

### Security Agents
- **InjectionAgent**: SQLi, XSS, command injection, path traversal (AST-based)
- **SSRFProtectionAgent**: HTTP client calls, protocol handlers, URL construction (AST-based)
- **CatchBlockAuditor**: Empty/bare catch blocks, Go error discard, Rust unwrap (AST-based)
