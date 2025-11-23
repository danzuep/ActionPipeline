using Microsoft.Extensions.Logging;

namespace ActionPipeline
{
    public sealed class DefaultLogger : ILogger
    {
        public static ILogger Instance { get; } = new DefaultLogger();

        private readonly ILogger _logger;

        private DefaultLogger(ILoggerFactory? loggerFactory = null)
        {
            loggerFactory ??= LoggerFactory.Create(builder => builder
#if DEBUG
                .SetMinimumLevel(LogLevel.Debug)
                .AddDebug()
#endif
                .AddConsole());

            _logger = loggerFactory.CreateLogger(nameof(DefaultLogger));
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return _logger.BeginScope(state);
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return _logger.IsEnabled(logLevel);
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            _logger.Log(logLevel, eventId, state, exception, formatter);
        }
    }
}