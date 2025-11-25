using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Binder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

var configurationRoot = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .Build();

var services = new ServiceCollection();
services.AddSingleton<IConfiguration>(configurationRoot);
services.AddSingleton<IConfigurationRoot>(configurationRoot);
services.AddSingleton(new ActivitySource("ConfigPipeline", "1.0"));
services.AddLogging(config =>
{
    config.AddSimpleConsole(options =>
    {
        options.TimestampFormat = "[HH:mm:ss] ";
        options.IncludeScopes = false;
    });
});
services.Configure<PolicyConfiguration>(configurationRoot.GetSection("PolicyConfig"));
services.AddSingleton<IPolicyRegistry, ReloadablePolicyRegistry>();
services.AddSingleton<IStageFactory, StageFactory>();
services.AddTransient<IDiagnosticCollector, DiagnosticCollector>();
services.AddTransient<ParsingStage>();
services.AddTransient<ValidationStage>();
services.AddTransient<DtoBindingStage>();
services.AddTransient<CompositeDtoBindingStage>();
services.AddSingleton<ConfigurationProcessor>();

var serviceProvider = services.BuildServiceProvider();
var processor = serviceProvider.GetRequiredService<ConfigurationProcessor>();
var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

logger.LogInformation("Starting configuration processing run #1");
var report1 = await processor.ProcessAsync();
PrintReport(report1, logger);

// Mutate policy definition to demonstrate runtime reload via IOptionsMonitor
configurationRoot["PolicyConfig:Policies:0:StageNames:2"] = "CompositeBind";
configurationRoot.Reload();
logger.LogInformation("Triggered configuration reload and switched stage for policy {Policy}", "app.settings.*");

var report2 = await processor.ProcessAsync();
PrintReport(report2, logger);

static void PrintReport(ProcessingReport report, ILogger logger)
{
    logger.LogInformation("Finished run in {ElapsedMilliseconds}ms", report.Duration.TotalMilliseconds);
    logger.LogInformation("Results:");
    foreach (var kvp in report.Results)
    {
        logger.LogInformation("  {Key}: {Value}", kvp.Key, kvp.Value);
    }

    if (!report.Diagnostics.Any())
    {
        logger.LogInformation("No diagnostics emitted.");
        return;
    }

    logger.LogInformation("Diagnostics:");
    foreach (var diag in report.Diagnostics)
    {
        logger.LogInformation(
            "  [{Severity}] {Category} ({CorrelationId:N}): {Message} {Remediation}",
            diag.Severity,
            diag.Category,
            diag.CorrelationId,
            diag.Message,
            string.IsNullOrEmpty(diag.Remediation) ? string.Empty : $"Remediation: {diag.Remediation}");
    }
}

#region Supporting types

public sealed record ProcessingReport(
    IReadOnlyDictionary<string, object> Results,
    IReadOnlyList<Diagnostic> Diagnostics,
    TimeSpan Duration);

public sealed record Diagnostic(
    string Message,
    string Category,
    Guid CorrelationId,
    DiagnosticSeverity Severity,
    string? Remediation = null);

public enum DiagnosticSeverity
{
    Info,
    Warning,
    Error
}

public interface IDiagnosticCollector
{
    void Record(Diagnostic diagnostic);
    IReadOnlyList<Diagnostic> Snapshot();
}

public sealed class DiagnosticCollector : IDiagnosticCollector
{
    private readonly List<Diagnostic> _diagnostics = new();

    public void Record(Diagnostic diagnostic) => _diagnostics.Add(diagnostic);

    public IReadOnlyList<Diagnostic> Snapshot() => _diagnostics.ToArray();
}

public sealed class PipelineContext
{
    public PipelineContext(
        string namespacePattern,
        string sectionPath,
        IReadOnlyDictionary<string, string> values,
        Type targetDtoType,
        IDiagnosticCollector diagnostics,
        ActivitySource activitySource)
    {
        NamespacePattern = namespacePattern;
        SectionPath = sectionPath;
        Values = values;
        TargetDtoType = targetDtoType;
        Diagnostics = diagnostics;
        ActivitySource = activitySource;
        CorrelationId = Guid.NewGuid();
    }

    public string NamespacePattern { get; }
    public string SectionPath { get; }
    public IReadOnlyDictionary<string, string> Values { get; }
    public Type TargetDtoType { get; }
    public IDiagnosticCollector Diagnostics { get; }
    public ActivitySource ActivitySource { get; }
    public Guid CorrelationId { get; }
    public IDictionary<string, object> Outputs { get; } = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
}

public sealed record StageResult(bool Success, Diagnostic? Diagnostic)
{
    public static StageResult Successful() => new(true, null);
    public static StageResult Failure(Diagnostic diagnostic) => new(false, diagnostic);
}

public interface IConfigurationStage
{
    Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken);
}

public abstract class ConfigurationStageBase : IConfigurationStage
{
    protected ConfigurationStageBase(ActivitySource activitySource, ILogger logger)
    {
        ActivitySource = activitySource;
        Logger = logger;
    }

    protected Activity? StartSpan(PipelineContext context, string stageName)
    {
        var activity = ActivitySource.StartActivity($"{stageName}:{context.SectionPath}", ActivityKind.Internal);
        if (activity is not null)
        {
            activity.SetTag("policy.namespace", context.NamespacePattern);
            activity.SetTag("correlation.id", context.CorrelationId);
        }

        return activity;
    }

    protected ActivitySource ActivitySource { get; }
    protected ILogger Logger { get; }

    public abstract Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken);
}

public sealed class ParsingStage : ConfigurationStageBase
{
    public ParsingStage(ActivitySource activitySource, ILogger<ParsingStage> logger)
        : base(activitySource, logger)
    {
    }

    public override Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken)
    {
        using var span = StartSpan(context, "Parsing");

        if (context.Values.Count == 0)
        {
            var diag = new Diagnostic(
                "No configuration values were found for the namespace.",
                "Parsing",
                context.CorrelationId,
                DiagnosticSeverity.Error,
                "Ensure at least one key/value exists under the policy namespace.");
            context.Diagnostics.Record(diag);
            Logger.LogWarning("Parsing failed for {Namespace}", context.NamespacePattern);
            return Task.FromResult(StageResult.Failure(diag));
        }

        context.Outputs["ParsedCount"] = context.Values.Count;
        var success = new Diagnostic(
            $"Parsed {context.Values.Count} entries in namespace {context.NamespacePattern}.",
            "Parsing",
            context.CorrelationId,
            DiagnosticSeverity.Info);
        context.Diagnostics.Record(success);
        Logger.LogInformation("Parsed {Count} entries for {Namespace}", context.Values.Count, context.NamespacePattern);
        return Task.FromResult(StageResult.Successful());
    }
}

public sealed class ValidationStage : ConfigurationStageBase
{
    public ValidationStage(ActivitySource activitySource, ILogger<ValidationStage> logger)
        : base(activitySource, logger)
    {
    }

    public override Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken)
    {
        using var span = StartSpan(context, "Validation");

        foreach (var kvp in context.Values)
        {
            if (string.IsNullOrEmpty(kvp.Key))
            {
                continue;
            }

            if (kvp.Key.EndsWith("port", StringComparison.OrdinalIgnoreCase) &&
                !int.TryParse(kvp.Value, out var port))
            {
                var diag = new Diagnostic(
                    $"'{kvp.Value}' is not a valid port number.",
                    "Validation",
                    context.CorrelationId,
                    DiagnosticSeverity.Error,
                    "Supply a numeric port (e.g., 5432).");
                context.Diagnostics.Record(diag);
                Logger.LogWarning("Validation failed for {Key}", kvp.Key);
                return Task.FromResult(StageResult.Failure(diag));
            }

            if (kvp.Key.EndsWith("timeout", StringComparison.OrdinalIgnoreCase) &&
                !int.TryParse(kvp.Value, out var timeout))
            {
                var diag = new Diagnostic(
                    $"'{kvp.Value}' is not a valid timeout value.",
                    "Validation",
                    context.CorrelationId,
                    DiagnosticSeverity.Warning,
                    "Use a whole number representing seconds.");
                context.Diagnostics.Record(diag);
                Logger.LogWarning("Validation warning for {Key}", kvp.Key);
            }

            if (kvp.Key.EndsWith("enabled", StringComparison.OrdinalIgnoreCase) &&
                !bool.TryParse(kvp.Value, out _))
            {
                var diag = new Diagnostic(
                    $"'{kvp.Value}' is not a valid boolean.",
                    "Validation",
                    context.CorrelationId,
                    DiagnosticSeverity.Error,
                    "Use 'true' or 'false'.");
                context.Diagnostics.Record(diag);
                Logger.LogWarning("Validation failed for {Key}", kvp.Key);
                return Task.FromResult(StageResult.Failure(diag));
            }
        }

        var success = new Diagnostic(
            "Validation succeeded.",
            "Validation",
            context.CorrelationId,
            DiagnosticSeverity.Info);
        context.Diagnostics.Record(success);
        return Task.FromResult(StageResult.Successful());
    }
}

public sealed class DtoBindingStage : ConfigurationStageBase
{
    private readonly IConfiguration _configuration;
    private readonly Type _targetType;

    public DtoBindingStage(IConfiguration configuration, ActivitySource activitySource, ILogger<DtoBindingStage> logger, Type targetType)
        : base(activitySource, logger)
    {
        _configuration = configuration;
        _targetType = targetType;
    }

    public override Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken)
    {
        using var span = StartSpan(context, "DtoBinding");

        var instance = Activator.CreateInstance(_targetType)!;
        var section = string.IsNullOrEmpty(context.SectionPath)
            ? _configuration
            : _configuration.GetSection(context.SectionPath);

        section.Bind(instance);
        context.Outputs[_targetType.Name] = instance;

        var diag = new Diagnostic(
            $"Bound DTO {_targetType.Name}.",
            "Binding",
            context.CorrelationId,
            DiagnosticSeverity.Info);
        context.Diagnostics.Record(diag);
        Logger.LogInformation("Bound DTO {DtoType} for {Namespace}", _targetType.Name, context.NamespacePattern);

        return Task.FromResult(StageResult.Successful());
    }
}

public sealed class CompositeDtoBindingStage : ConfigurationStageBase
{
    private readonly IConfiguration _configuration;
    private readonly Type _targetType;

    public CompositeDtoBindingStage(IConfiguration configuration, ActivitySource activitySource, ILogger<CompositeDtoBindingStage> logger, Type targetType)
        : base(activitySource, logger)
    {
        _configuration = configuration;
        _targetType = targetType;
    }

    public override Task<StageResult> ExecuteAsync(PipelineContext context, CancellationToken cancellationToken)
    {
        using var span = StartSpan(context, "CompositeBinding");

        var instance = Activator.CreateInstance(_targetType)!;
        _configuration.GetSection(context.SectionPath).Bind(instance);

        if (instance is DatabaseConnectionDto dto)
        {
            dto.Credentials ??= new DatabaseCredentials();
            _configuration.GetSection($"{context.SectionPath}.credentials").Bind(dto.Credentials);
        }

        context.Outputs[$"{_targetType.Name}.Composite"] = instance;

        var diag = new Diagnostic(
            $"Composite DTO {_targetType.Name} materialized with hierarchical sections.",
            "HierarchicalBinding",
            context.CorrelationId,
            DiagnosticSeverity.Info);
        context.Diagnostics.Record(diag);
        Logger.LogInformation("Created composite DTO {DtoType} for {Namespace}", _targetType.Name, context.NamespacePattern);

        return Task.FromResult(StageResult.Successful());
    }
}

public interface IStageFactory
{
    IConfigurationStage Create(string stageName, Type targetType);
}

public sealed class StageFactory : IStageFactory
{
    private readonly IServiceProvider _serviceProvider;

    public StageFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public IConfigurationStage Create(string stageName, Type targetType)
    {
        return stageName switch
        {
            "Parse" => _serviceProvider.GetRequiredService<ParsingStage>(),
            "Validate" => _serviceProvider.GetRequiredService<ValidationStage>(),
            "DtoBind" => ActivatorUtilities.CreateInstance<DtoBindingStage>(_serviceProvider, targetType),
            "CompositeBind" => ActivatorUtilities.CreateInstance<CompositeDtoBindingStage>(_serviceProvider, targetType),
            _ => throw new InvalidOperationException($"Unknown stage '{stageName}'.")
        };
    }
}

public sealed class ConfigurationProcessor
{
    private readonly IConfiguration _configuration;
    private readonly IPolicyRegistry _policyRegistry;
    private readonly IStageFactory _stageFactory;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<ConfigurationProcessor> _logger;
    private readonly ActivitySource _activitySource;

    public ConfigurationProcessor(
        IConfiguration configuration,
        IPolicyRegistry policyRegistry,
        IStageFactory stageFactory,
        IServiceProvider serviceProvider,
        ILogger<ConfigurationProcessor> logger,
        ActivitySource activitySource)
    {
        _configuration = configuration;
        _policyRegistry = policyRegistry;
        _stageFactory = stageFactory;
        _serviceProvider = serviceProvider;
        _logger = logger;
        _activitySource = activitySource;
    }

    public async Task<ProcessingReport> ProcessAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var results = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        var diagnostics = new List<Diagnostic>();

        foreach (var policy in _policyRegistry.GetPolicies())
        {
            var (sectionPath, values) = ExtractPolicyValues(policy);
            if (values.Count == 0)
            {
                _logger.LogDebug("Policy {Namespace} had no matching values.", policy.NamespacePattern);
                continue;
            }

            var diagCollector = _serviceProvider.GetRequiredService<IDiagnosticCollector>();
            var context = new PipelineContext(
                policy.NamespacePattern,
                sectionPath,
                values,
                policy.TargetDtoType,
                diagCollector,
                _activitySource);

            foreach (var stageName in policy.StageNames)
            {
                var stage = _stageFactory.Create(stageName, policy.TargetDtoType);
                var stageResult = await stage.ExecuteAsync(context, cancellationToken);
                if (!stageResult.Success)
                {
                    if (stageResult.Diagnostic is not null)
                    {
                        diagnostics.Add(stageResult.Diagnostic);
                    }

                    _logger.LogWarning("Stage {Stage} short-circuited for policy {Policy}", stageName, policy.NamespacePattern);
                    break;
                }
            }

            diagnostics.AddRange(context.Diagnostics.Snapshot());
            foreach (var kvp in context.Outputs)
            {
                results[kvp.Key] = kvp.Value;
            }
        }

        stopwatch.Stop();
        return new ProcessingReport(results, diagnostics, stopwatch.Elapsed);
    }

    private (string SectionPath, IReadOnlyDictionary<string, string> Values) ExtractPolicyValues(PolicyDefinition policy)
    {
        var wildcardPrefix = policy.NamespacePattern.EndsWith('*')
            ? policy.NamespacePattern[..^1]
            : policy.NamespacePattern;
        var sectionPath = wildcardPrefix.TrimEnd('.');
        var keyPrefix = string.IsNullOrEmpty(sectionPath)
            ? string.Empty
            : sectionPath + '.';

        var matched = _configuration.AsEnumerable()
            .Where(pair => pair.Value is not null &&
                           (string.IsNullOrEmpty(keyPrefix)
                               ? !string.IsNullOrEmpty(pair.Value)
                               : pair.Key.Equals(sectionPath, StringComparison.OrdinalIgnoreCase) ||
                                 pair.Key.StartsWith(keyPrefix, StringComparison.OrdinalIgnoreCase)))
            .ToDictionary(
                pair =>
                {
                    if (string.IsNullOrEmpty(keyPrefix) || pair.Key.Equals(sectionPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Empty;
                    }

                    return pair.Key[keyPrefix.Length..];
                },
                pair => pair.Value!,
                StringComparer.OrdinalIgnoreCase);

        return (sectionPath, matched);
    }
}

public interface IPolicyRegistry
{
    IReadOnlyList<PolicyDefinition> GetPolicies();
}

public sealed class PolicyDefinition(string NamespacePattern, string[] StageNames, Type TargetDtoType);

public sealed class ReloadablePolicyRegistry : IPolicyRegistry
{
    private readonly ILogger<ReloadablePolicyRegistry> _logger;
    private volatile IReadOnlyList<PolicyDefinition> _definitions = Array.Empty<PolicyDefinition>();

    public ReloadablePolicyRegistry(IOptionsMonitor<PolicyConfiguration> monitor, ILogger<ReloadablePolicyRegistry> logger)
    {
        _logger = logger;
        monitor.OnChange(cfg =>
        {
            _definitions = Build(cfg);
            _logger.LogInformation("Policy registry reloaded with {Count} definitions.", _definitions.Count);
        });
        _definitions = Build(monitor.CurrentValue);
    }

    public IReadOnlyList<PolicyDefinition> GetPolicies() => _definitions;

    private static IReadOnlyList<PolicyDefinition> Build(PolicyConfiguration config)
    {
        var policies = config?.Policies ?? Array.Empty<PolicyOptions>();
        return policies
            .Select(option =>
            {
                var targetType = KnownDtoTypes.Map.TryGetValue(option.TargetTypeKey ?? string.Empty, out var type)
                    ? type
                    : typeof(Dictionary<string, string>);
                return new PolicyDefinition(
                    option.NamespacePattern ?? string.Empty,
                    option.StageNames ?? Array.Empty<string>(),
                    targetType);
            })
            .ToList();
    }
}

public sealed class PolicyConfiguration
{
    public List<PolicyOptions> Policies { get; set; } = new();
}

public sealed class PolicyOptions
{
    public string NamespacePattern { get; set; } = string.Empty;
    public string[] StageNames { get; set; } = Array.Empty<string>();
    public string TargetTypeKey { get; set; } = string.Empty;
}

public static class KnownDtoTypes
{
    public static readonly IReadOnlyDictionary<string, Type> Map = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
    {
        ["AppSettings"] = typeof(AppSettingsDto),
        ["DatabaseConnection"] = typeof(DatabaseConnectionDto)
    };
}

public sealed class AppSettingsDto
{
    public string? Theme { get; set; }
    public int Timeout { get; set; }

    public override string ToString() => $"Theme={Theme ?? "(null)"}, Timeout={Timeout}";
}

public sealed class DatabaseConnectionDto
{
    public string? Host { get; set; }
    public int Port { get; set; }
    public DatabaseCredentials? Credentials { get; set; }

    public override string ToString() =>
        $"Host={Host ?? "(null)"}, Port={Port}, Credentials=[{Credentials}]";
}

public sealed class DatabaseCredentials
{
    public string? User { get; set; }
    public string? Password { get; set; }

    public override string ToString() => $"User={User ?? "(null)"}";
}

#endregion