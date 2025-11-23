# ActionPlan - Configuration Processing System

A clean, testable pipeline for processing hierarchical key/value configuration with namespace-aware policies, typed results, and structured diagnostics.

---

## Overview

This project implements a C# configuration-processing system designed to:

- centralize orchestration in an injectable service
- run a pipeline of handlers (parsing, validation, transformation) where each handler returns a typed result and can short-circuit on failure
- dynamically select and order handlers based on namespace-based node policies
- allow policies to define handler sequences, validators, and transformation strategies
- wire policies into the pipeline via a builder/registry and DI
- emit final normalized results with aggregated, structured diagnostics

Sample policies are provided to demonstrate theme, database port, and feature flags, covering string, numeric, and boolean handling.

---

## Design Highlights

### Key Components

- **IActionPlanProcessor**: Central orchestrator for processing input key/value pairs through a policy-driven pipeline.
- **Pipeline of Handlers**: Parsing, validation, and transformation stages. Each handler:
  - returns a typed result (e.g., string, int, bool)
  - can short-circuit on failure
  - exposes diagnostics (structured messages, severity, location)
- **Node Policies**: Namespace-based rules that influence:
  - preferred handler sequence
  - which validators to apply
  - which transformation strategies to use
- **Policy Registry / Builder**: Maps namespace patterns to policy definitions and wires them into the pipeline via DI.
- **Final Result**: Normalized, typed values with an aggregated diagnostics object for the caller.
- **Sample Policies**:
  - `app.settings.*` (strings, options)
  - `database.connection.*` (numeric ports, etc.)
  - `feature.flags.*` (boolean toggles)

### Architectural Threads

- **Dependency Injection (DI)**: `Microsoft.Extensions.DependencyInjection` for wiring services, policies, and pipelines.
- **Logging**: `ILogger<T>` for traceability at each pipeline stage.
- **Validation**: FluentValidation (or an in-house lightweight validator) to express policy-driven checks.
- **Immutability & Value Objects**: Use records/Value Objects to model results and diagnostics.
- **Testing**: NUnit-based unit tests cover parsing, validation, transformation, policy resolution, and end-to-end processing.

---

## Major Components & How They Fit Together

- **Input Model**
  - A collection of key/value pairs with hierarchical keys like `app.settings.theme` or `database.connection.port`.

- **Policy Registry / Builder**
  - Maintains mappings from namespace patterns (e.g., `app.settings.*`) to policy definitions.
  - Builds a pipeline descriptor for the given input, selecting handlers and validators.

- **Handler Pipeline**
  - Parsing Handler: converts raw values to intermediate typed representations (e.g., string, int, bool as applicable).
  - Validation Handler: enforces domain constraints (e.g., required keys, value ranges).
  - Transformation Handler: applies final conversions into the normalized value (e.g., mapping to IOptions-like structures or strongly-typed POCOs).

- **Diagnostics / Result Model**
  - Structured diagnostics: diagnostic code, message, severity, and location (key path).
  - Aggregated diagnostics for the caller, with the final typed result if successful.

- **Runner / Processor**
  - `IActionPlanProcessor` implementation coordinates policy resolution, executes pipeline, aggregates results and diagnostics, and returns a well-defined outcome.

---

## Testing

- NUnit tests cover:
  - Policy resolution and namespace matching
  - Individual handler correctness (parsing, validation, transformation)
  - End-to-end processing across sample policies
  - Diagnostic aggregation and failure modes

---

## Project Structure (High-Level)

- Core
  - IActionPlanProcessor
  - ActionPlanProcessor
  - IParserHandler, IValidatorHandler, ITransformerHandler
  - Policy-related interfaces: IPolicyProvider, IPolicyRegistry, IPolicyResolver
  - Diagnostics: Diagnostic, DiagnosticSeverity, DiagnosticsBag
  - ValueObjects: TypedResult, NormalizedValue, etc.

- Policies
  - SamplePolicyProvider (theme, database port, feature flags)
  - PolicyRegistry/PolicyResolver implementations

- Tests
  - Unit tests for parser/validator/transformer
  - Policy resolution tests
  - End-to-end processing tests with NUnit

---

## Quick Start Checklist

- [x] Create DI container and register policy registry, policy provider, and action plan processor
- [x] Implement or register parser, validator, and transformer handlers
- [x] Define policy mappings for desired namespaces (e.g., app.settings.*, database.connection.*)
- [x] Provide input key/value pairs
- [x] Run processor and inspect normalized results and diagnostics
