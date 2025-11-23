using System.Globalization;
using ActionPipeline;
using Microsoft.Extensions.Logging;

public interface IInputHandler
{
    bool TryHandle(KeyValuePair<string, string> input, out object? parsedValue);
}

public interface ITransformationStrategy
{
    object? Transform(object? value);
}

public class StringValueHandler : IInputHandler
{
    public bool TryHandle(KeyValuePair<string, string> input, out object? parsedValue)
    {
        var trimmed = input.Value?.Trim();
        parsedValue = trimmed;
        return trimmed is not null;
    }
}

public class NumericValueHandler : IInputHandler
{
    public bool TryHandle(KeyValuePair<string, string> input, out object? parsedValue)
    {
        parsedValue = null;
        if (long.TryParse(input.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue))
        {
            parsedValue = longValue;
            return true;
        }

        if (double.TryParse(input.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var doubleValue))
        {
            parsedValue = doubleValue;
            return true;
        }

        return false;
    }
}

public class BooleanValueHandler : IInputHandler
{
    public bool TryHandle(KeyValuePair<string, string> input, out object? parsedValue)
    {
        if (bool.TryParse(input.Value?.Trim(), out var boolValue))
        {
            parsedValue = boolValue;
            return true;
        }

        parsedValue = null;
        return false;
    }
}

public class LowercaseStrategy : ITransformationStrategy
{
    public object? Transform(object? value)
    {
        return value switch
        {
            string s => s.ToLowerInvariant(),
            _ => value
        };
    }
}

public class ActionPlan
{
    private readonly List<IInputHandler> _handlers = new();
    private readonly List<ITransformationStrategy> _transformations = new();
    private readonly List<Func<KeyValuePair<string, object?>, ValidationResult>> _validators = new();
    private readonly IEnumerable<KeyValuePair<string, string>> _inputs;

    public ActionPlan(IEnumerable<KeyValuePair<string, string>> inputs)
    {
        _inputs = inputs ?? throw new ArgumentNullException(nameof(inputs));
    }

    public ActionPlan AddHandler(IInputHandler handler)
    {
        _handlers.Add(handler);
        return this;
    }

    public ActionPlan AddTransformation(ITransformationStrategy transformation)
    {
        _transformations.Add(transformation);
        return this;
    }

    public ActionPlan AddFluentValidation(Action<FluentValidationBuilder> configure)
    {
        var builder = new FluentValidationBuilder();
        configure(builder);
        _validators.AddRange(builder.Build());
        return this;
    }

    public IReadOnlyList<KeyValuePair<string, object?>> Apply()
    {
        var results = new List<KeyValuePair<string, object?>>();

        foreach (var input in _inputs)
        {
            foreach (var handler in _handlers)
            {
                if (handler.TryHandle(input, out var parsedValue))
                {
                    var kvp = new KeyValuePair<string, object?>(input.Key, parsedValue);
                    if (_validators.All(validate => validate(kvp).IsValid))
                    {
                        var transformed = _transformations.Aggregate(parsedValue, (current, transformer) => transformer.Transform(current));
                        results.Add(new KeyValuePair<string, object?>(input.Key, transformed));
                    }

                    break;
                }
            }
        }

        return results;
    }
}

public class FluentValidationBuilder
{
    private readonly List<Func<KeyValuePair<string, object?>, ValidationResult>> _rules = new();

    public FluentValidationBuilder AddRule(
        Func<KeyValuePair<string, object?>, bool> predicate,
        string errorMessage)
    {
        _rules.Add(kvp => predicate(kvp)
            ? ValidationResult.Success
            : ValidationResult.Fail(errorMessage));

        return this;
    }

    public IReadOnlyList<Func<KeyValuePair<string, object?>, ValidationResult>> Build() => _rules;
}

public readonly record struct ValidationResult(bool IsValid, string? Message)
{
    public static ValidationResult Success => new(true, null);
    public static ValidationResult Fail(string message) => new(false, message);
}

public class Program
{
    public static void Main()
    {
        var logger = DefaultLogger.Instance;

        var input = new List<KeyValuePair<string, string>>
        {
            new("app.settings.theme", " Dark "),
            new("database.connection.port", "5432"),
            new("featureFlags.beta", "true")
        };

        var results = new ActionPlan(input)
            .AddFluentValidation(builder => builder
                .AddRule(kvp => !string.IsNullOrWhiteSpace(kvp.Value?.ToString()), "Value cannot be empty"))
            .AddHandler(new StringValueHandler())
            .AddHandler(new NumericValueHandler())
            .AddHandler(new BooleanValueHandler())
            .AddTransformation(new LowercaseStrategy())
            .Apply();

        logger.LogInformation("Final values:");
        foreach (var kvp in results)
        {
            logger.LogInformation($"{kvp.Key} = {kvp.Value}");
        }
    }
}