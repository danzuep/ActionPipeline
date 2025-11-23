using System.Text.RegularExpressions;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

public record ConfigEntry(string Key, string Value);

public enum DiagnosticSeverity
{
    Info,
    Warning,
    Error
}

public record Diagnostic(string Stage, string Code, string Message, DiagnosticSeverity Severity, string? NodeKey = null);

public class HandlerResult
{
    public bool Success { get; }
    public object? Value { get; }
    public IReadOnlyList<Diagnostic> Diagnostics { get; }

    protected HandlerResult(bool success, object? value, IEnumerable<Diagnostic>? diagnostics)
    {
        Success = success;
        Value = value;
        Diagnostics = diagnostics?.ToList() ?? new List<Diagnostic>();
    }

    public static HandlerResult SuccessResult(object value, IEnumerable<Diagnostic>? diagnostics = null) =>
        new(true, value, diagnostics);

    public static HandlerResult Failure(IEnumerable<Diagnostic>? diagnostics = null) =>
        new(false, null, diagnostics);

    public static HandlerResult<T> SuccessResult<T>(T value, IEnumerable<Diagnostic>? diagnostics = null) =>
        new(value, true, diagnostics);

    public static HandlerResult<T> Failure<T>(IEnumerable<Diagnostic>? diagnostics = null) =>
        new(default!, false, diagnostics);
}

public class HandlerResult<T> : HandlerResult
{
    public new T Value => (T)base.Value!;

    public HandlerResult(T value, bool success = true, IEnumerable<Diagnostic>? diagnostics = null)
        : base(success, value, diagnostics)
    {
    }

    protected HandlerResult(bool success, object? value, IEnumerable<Diagnostic>? diagnostics)
        : base(success, value, diagnostics)
    {
    }
}

public interface IPipelineStage
{
    public Type InputType { get; }
    public Type OutputType { get; }
    Task<HandlerResult> ExecuteAsync(object input, CancellationToken cancellationToken);
}

public abstract class PipelineStage<TIn, TOut> : IPipelineStage
{
    public Type InputType => typeof(TIn);
    public Type OutputType => typeof(TOut);

    public async Task<HandlerResult> ExecuteAsync(object input, CancellationToken cancellationToken)
    {
        if (input is not TIn typedInput)
        {
            throw new InvalidOperationException($"Stage {GetType().Name} expected {typeof(TIn)}, but got {input?.GetType()}.");
        }

        var result = await ExecuteAsync(typedInput, cancellationToken).ConfigureAwait(false);
        return result;
    }

    public abstract Task<HandlerResult<TOut>> ExecuteAsync(TIn input, CancellationToken cancellationToken);
}

public interface IActionPlanProcessor
{
    Task<ProcessingOutcome> ProcessAsync(IEnumerable<ConfigEntry> entries, CancellationToken cancellationToken = default);
}

public record ProcessingOutcome(IReadOnlyList<NormalizedConfigValue> Results, IReadOnlyList<Diagnostic> Diagnostics);

public record NormalizedConfigValue(string NodeKey, object Value, Type ValueType);

public sealed class ActionPlanProcessor : IActionPlanProcessor
{
    private readonly NodePolicyCatalog _catalog;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<ActionPlanProcessor> _logger;

    public ActionPlanProcessor(NodePolicyCatalog catalog, IServiceProvider serviceProvider, ILogger<ActionPlanProcessor> logger)
    {
        _catalog = catalog;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task<ProcessingOutcome> ProcessAsync(IEnumerable<ConfigEntry> entries, CancellationToken cancellationToken = default)
    {
        var results = new List<NormalizedConfigValue>();
        var diagnostics = new List<Diagnostic>();

        foreach (var entry in entries)
        {
            var policy = _catalog.Resolve(entry.Key);
            if (policy is null)
            {
                var missing = new Diagnostic("PolicyResolution", "POLICY_MISSING",
                    $"No policy matched node '{entry.Key}'.", DiagnosticSeverity.Error, entry.Key);
                diagnostics.Add(missing);
                continue;
            }

            object current = entry;
            bool failed = false;
            IPipelineStage? lastStage = null;
            HandlerResult? lastResult = null;

            foreach (var stageType in policy.StageTypes)
            {
                var stage = _serviceProvider.GetService(stageType) as IPipelineStage;
                if (stage is null)
                {
                    var diag = new Diagnostic("StageResolution", "STAGE_MISSING",
                        $"Stage '{stageType.Name}' could not be resolved for '{entry.Key}'.", DiagnosticSeverity.Error, entry.Key);
                    diagnostics.Add(diag);
                    failed = true;
                    break;
                }
                lastStage = stage;

                var stageResult = await stage.ExecuteAsync(current, cancellationToken).ConfigureAwait(false);
                lastResult = stageResult;

                var contextualDiagnostics = stageResult.Diagnostics
                    .Select(d => d with { NodeKey = entry.Key, Stage = stageType.Name })
                    .ToList();
                diagnostics.AddRange(contextualDiagnostics);

                if (!stageResult.Success)
                {
                    failed = true;
                    _logger.LogInformation("Stage {Stage} failed for '{Key}'.", stageType.Name, entry.Key);
                    break;
                }

                if (stageResult.Value is null)
                {
                    var nullDiag = new Diagnostic(stageType.Name, "NULL_STAGE_OUTPUT",
                        $"Stage returned no value for '{entry.Key}'.", DiagnosticSeverity.Error, entry.Key);
                    diagnostics.Add(nullDiag);
                    failed = true;
                    break;
                }

                current = stageResult.Value!;
            }

            if (failed || lastStage is null || lastResult is null || !lastResult.Success)
            {
                continue;
            }

            results.Add(new NormalizedConfigValue(entry.Key, lastResult.Value!, lastStage.OutputType));
        }

        return new ProcessingOutcome(results, diagnostics);
    }
}

public class NodePolicyCatalog
{
    private readonly List<NodePolicyDefinition> _definitions;

    public NodePolicyCatalog(IEnumerable<NodePolicyDefinition> definitions)
    {
        _definitions = definitions.OrderByDescending(d => d.Pattern.Length).ToList();
    }

    public NodePolicyDefinition? Resolve(string nodeKey) => _definitions.FirstOrDefault(def => def.PatternRegex.IsMatch(nodeKey));
}

public sealed class NodePolicyDefinition
{
    public string Pattern { get; }
    public Regex PatternRegex { get; }
    public IReadOnlyList<Type> StageTypes { get; }

    public NodePolicyDefinition(string pattern, IEnumerable<Type> stageTypes)
    {
        Pattern = pattern;
        PatternRegex = new Regex("^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$", RegexOptions.Compiled);
        StageTypes = stageTypes.ToList();
    }
}

public sealed class NodePolicyCatalogBuilder
{
    private readonly List<NodePolicyDefinition> _definitions = new();

    public NodePolicyCatalogBuilder AddPolicy(string pattern, Action<PolicyStageSequenceBuilder> configure)
    {
        var builder = new PolicyStageSequenceBuilder(pattern);
        configure(builder);
        var definition = builder.Build();
        _definitions.Add(definition);
        return this;
    }

    public NodePolicyCatalog Build() => new(_definitions);
}

public sealed class PolicyStageSequenceBuilder
{
    private readonly string _pattern;
    private readonly List<Type> _stages = new();

    public PolicyStageSequenceBuilder(string pattern)
    {
        _pattern = pattern;
    }

    public PolicyStageSequenceBuilder Stage<TStage>() where TStage : IPipelineStage => Stage(typeof(TStage));

    public PolicyStageSequenceBuilder Stage(Type stageType)
    {
        if (!typeof(IPipelineStage).IsAssignableFrom(stageType))
        {
            throw new ArgumentException($"Stage {stageType.Name} must implement IPipelineStage.");
        }

        _stages.Add(stageType);
        return this;
    }

    public NodePolicyDefinition Build()
    {
        if (!_stages.Any())
        {
            throw new InvalidOperationException($"Policy '{_pattern}' must define at least one stage.");
        }

        if (_stages.FirstOrDefault() is not null && _stages.First() is Type firstStage && firstStage == null)
        {
            throw new InvalidOperationException("Parser stage must be first.");
        }

        return new NodePolicyDefinition(_pattern, _stages);
    }
}

// Domain Models
public record ThemeOptions(string ThemeName);
public record DatabasePortOptions(int Port);
public record FeatureFlagOptions(bool Enabled);

// Parsers
public class StringParserStage : PipelineStage<ConfigEntry, string>
{
    public override Task<HandlerResult<string>> ExecuteAsync(ConfigEntry input, CancellationToken cancellationToken)
    {
        var trimmed = input.Value?.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            var diag = new Diagnostic("StringParser", "EMPTY_VALUE", "Value cannot be empty.", DiagnosticSeverity.Error);
            return Task.FromResult(HandlerResult.Failure<string>(new[] { diag }));
        }

        return Task.FromResult(new HandlerResult<string>(trimmed));
    }
}

public class IntParserStage : PipelineStage<ConfigEntry, int>
{
    public override Task<HandlerResult<int>> ExecuteAsync(ConfigEntry input, CancellationToken cancellationToken)
    {
        if (!int.TryParse(input.Value, out var parsed))
        {
            var diag = new Diagnostic("IntParser", "INVALID_INT", $"'{input.Value}' is not a valid integer.", DiagnosticSeverity.Error);
            return Task.FromResult(HandlerResult.Failure<int>(new[] { diag }));
        }

        return Task.FromResult(new HandlerResult<int>(parsed));
    }
}

public class BooleanParserStage : PipelineStage<ConfigEntry, bool>
{
    private static readonly Dictionary<string, bool> TruthyValues = new()
    {
        ["true"] = true,
        ["yes"] = true,
        ["1"] = true,
        ["false"] = false,
        ["no"] = false,
        ["0"] = false
    };

    public override Task<HandlerResult<bool>> ExecuteAsync(ConfigEntry input, CancellationToken cancellationToken)
    {
        var normalized = input.Value?.Trim().ToLowerInvariant();
        if (normalized is null || !TruthyValues.TryGetValue(normalized, out var parsed))
        {
            var diag = new Diagnostic("BooleanParser", "INVALID_BOOL", $"'{input.Value}' is not a recognized boolean.", DiagnosticSeverity.Error);
            return Task.FromResult(HandlerResult.Failure<bool>(new[] { diag }));
        }

        return Task.FromResult(new HandlerResult<bool>(parsed));
    }
}

// Validators & FluentValidation
public class ThemeNameValidator : AbstractValidator<string>
{
    public ThemeNameValidator()
    {
        RuleFor(theme => theme)
            .NotEmpty()
            .WithMessage("Theme cannot be empty.")
            .Must(theme => theme.All(char.IsLetterOrDigit))
            .WithMessage("Theme can only contain letters and digits.");
    }
}

public class ThemeNameValidationStage : PipelineStage<string, string>
{
    private readonly IValidator<string> _validator;

    public ThemeNameValidationStage(IValidator<string> validator)
    {
        _validator = validator;
    }

    public override Task<HandlerResult<string>> ExecuteAsync(string input, CancellationToken cancellationToken)
    {
        var validation = _validator.Validate(input);
        if (!validation.IsValid)
        {
            var diag = validation.Errors.Select(error =>
                new Diagnostic("ThemeValidation", "FLUENT_VALIDATION", error.ErrorMessage, DiagnosticSeverity.Error));
            return Task.FromResult(HandlerResult.Failure<string>(diag));
        }

        return Task.FromResult(new HandlerResult<string>(input));
    }
}

public class PortRangeValidationStage : PipelineStage<int, int>
{
    public override Task<HandlerResult<int>> ExecuteAsync(int input, CancellationToken cancellationToken)
    {
        if (input < 1 || input > 65535)
        {
            var diag = new Diagnostic("PortValidation", "PORT_OUT_OF_RANGE", "Port must be between 1 and 65535.", DiagnosticSeverity.Error);
            return Task.FromResult(HandlerResult.Failure<int>(new[] { diag }));
        }

        return Task.FromResult(new HandlerResult<int>(input));
    }
}

// Transformers
public class ThemeOptionsTransformer : PipelineStage<string, ThemeOptions>
{
    public override Task<HandlerResult<ThemeOptions>> ExecuteAsync(string input, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HandlerResult<ThemeOptions>(new ThemeOptions(input)));
    }
}

public class DatabasePortOptionsTransformer : PipelineStage<int, DatabasePortOptions>
{
    public override Task<HandlerResult<DatabasePortOptions>> ExecuteAsync(int input, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HandlerResult<DatabasePortOptions>(new DatabasePortOptions(input)));
    }
}

public class FeatureFlagOptionsTransformer : PipelineStage<bool, FeatureFlagOptions>
{
    public override Task<HandlerResult<FeatureFlagOptions>> ExecuteAsync(bool input, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HandlerResult<FeatureFlagOptions>(new FeatureFlagOptions(input)));
    }
}

// DI & Policy Registration
public static class ConfigurationProcessingExtensions
{
    public static IServiceCollection AddConfigurationProcessing(this IServiceCollection services, Action<NodePolicyCatalogBuilder> configurePolicies)
    {
        var builder = new NodePolicyCatalogBuilder();
        configurePolicies(builder);
        services.AddSingleton(builder.Build());
        services.AddSingleton<IActionPlanProcessor, ActionPlanProcessor>();
        return services;
    }

    public static NodePolicyCatalogBuilder AddSamplePolicies(this NodePolicyCatalogBuilder builder)
    {
        builder.AddPolicy("app.settings.theme", policy => policy
            .Stage<StringParserStage>()
            .Stage<ThemeNameValidationStage>()
            .Stage<ThemeOptionsTransformer>());

        builder.AddPolicy("database.connection.port", policy => policy
            .Stage<IntParserStage>()
            .Stage<PortRangeValidationStage>()
            .Stage<DatabasePortOptionsTransformer>());

        builder.AddPolicy("features.*", policy => policy
            .Stage<BooleanParserStage>()
            .Stage<FeatureFlagOptionsTransformer>());

        return builder;
    }
}

public static class Program
{
    public static async Task Main()
    {
        var services = new ServiceCollection();

        services.AddLogging(configure => configure.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = "HH:mm:ss ";
        }));

        // Register pipeline stages and validators
        services.AddTransient<StringParserStage>();
        services.AddTransient<IntParserStage>();
        services.AddTransient<BooleanParserStage>();
        services.AddTransient<ThemeNameValidationStage>();
        services.AddTransient<PortRangeValidationStage>();
        services.AddTransient<ThemeOptionsTransformer>();
        services.AddTransient<DatabasePortOptionsTransformer>();
        services.AddTransient<FeatureFlagOptionsTransformer>();
        services.AddTransient<IValidator<string>, ThemeNameValidator>();

        services.AddConfigurationProcessing(builder => builder.AddSamplePolicies());

        using var provider = services.BuildServiceProvider();
        var logger = provider.GetRequiredService<ILogger<ActionPlanProcessor>>();
        var processor = provider.GetRequiredService<IActionPlanProcessor>();

        var entries = new[]
        {
            new ConfigEntry("app.settings.theme", " dark"),
            new ConfigEntry("database.connection.port", "27017"),
            new ConfigEntry("features.new-dashboard", "yes")
        };

        var outcome = await processor.ProcessAsync(entries);

        foreach (var result in outcome.Results)
        {
            logger.LogInformation("Node '{Key}' normalized to {Type} -> {Value}.", result.NodeKey, result.ValueType.Name, result.Value);
        }

        foreach (var diag in outcome.Diagnostics)
        {
            logger.LogWarning("Diagnostics [{Node}][{Stage}] {Code}: {Message}", diag.NodeKey ?? "<unknown>", diag.Stage, diag.Code, diag.Message);
        }
    }
}