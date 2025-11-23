using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace ActionPipeline.Tests;

[TestFixture]
public class ActionPlanProcessorTests
{
    private IServiceProvider _provider = null!;

    [OneTimeSetUp]
    public void SetUp()
    {
        var services = new ServiceCollection();
        services.AddLogging();

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

        _provider = services.BuildServiceProvider();
    }

    [OneTimeTearDown]
    public void TearDown()
    {
        if (_provider is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    [Test]
    public async Task Process_AppTheme_ProducesThemeOptions()
    {
        var processor = _provider.GetRequiredService<IActionPlanProcessor>();

        var entry = new ConfigEntry("app.settings.theme", "DarkMode");
        var outcome = await processor.ProcessAsync([entry]);

        Assert.That(outcome.Results, Has.Exactly(1).Items);
        var result = outcome.Results.Single();
        Assert.That(result.Value, Is.EqualTo(new ThemeOptions("DarkMode")));
        Assert.That(result.ValueType, Is.EqualTo(typeof(ThemeOptions)));
        Assert.That(outcome.Diagnostics, Is.Empty);
    }

    [Test]
    public async Task Process_DatabasePortInvalid_ProducesDiagnostic()
    {
        var processor = _provider.GetRequiredService<IActionPlanProcessor>();

        var entry = new ConfigEntry("database.connection.port", "90000");
        var outcome = await processor.ProcessAsync([entry]);

        Assert.That(outcome.Results, Is.Empty);
        Assert.That(outcome.Diagnostics, Has.Some.Matches<Diagnostic>(
            d => d.NodeKey == entry.Key && d.Code == "PORT_OUT_OF_RANGE"));
    }

    [Test]
    public async Task Process_FeatureFlagSuccess_ReturnsBooleanOption()
    {
        var processor = _provider.GetRequiredService<IActionPlanProcessor>();

        var entry = new ConfigEntry("features.experimental-ui", "yes");
        var outcome = await processor.ProcessAsync([entry]);

        Assert.That(outcome.Diagnostics, Is.Empty);
        Assert.That(outcome.Results.Single().Value, Is.EqualTo(new FeatureFlagOptions(true)));
    }

    [Test]
    public async Task Process_UnmatchedNode_ProducesDiagnostic()
    {
        var processor = _provider.GetRequiredService<IActionPlanProcessor>();

        var entry = new ConfigEntry("unmatched.node", "value");
        var outcome = await processor.ProcessAsync([entry]);

        Assert.That(outcome.Results, Is.Empty);
        Assert.That(outcome.Diagnostics, Has.Some.Matches<Diagnostic>(
            d => d.NodeKey == entry.Key && d.Code == "POLICY_MISSING"));
    }
}