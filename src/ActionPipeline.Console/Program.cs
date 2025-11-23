using System.Collections;

namespace ActionPipeline
{
    public class ConfigurationNode
    {
        public string Path { get; }
        public object Value { get; set; }
        public List<ConfigurationNode> Children { get; } = new();

        public ConfigurationNode(string path, object value)
        {
            Path = path;
            Value = value;
        }

        public void AddChild(ConfigurationNode child) => Children.Add(child);
    }

    public class ConfigurationNodeIterator : IEnumerable<ConfigurationNode>
    {
        private readonly ConfigurationNode _root;

        public ConfigurationNodeIterator(ConfigurationNode root) => _root = root;

        public IEnumerator<ConfigurationNode> GetEnumerator()
        {
            var stack = new Stack<ConfigurationNode>();
            stack.Push(_root);

            while (stack.Count > 0)
            {
                var node = stack.Pop();
                yield return node;
                for (var i = node.Children.Count - 1; i >= 0; i--)
                    stack.Push(node.Children[i]);
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public interface IValueHandler
    {
        void Handle(ConfigurationNode node);
        IValueHandler SetNext(IValueHandler next);
    }

    public abstract class ValueHandlerBase : IValueHandler
    {
        protected IValueHandler Next;

        public IValueHandler SetNext(IValueHandler next)
        {
            Next = next;
            return next;
        }

        public void Handle(ConfigurationNode node)
        {
            if (CanHandle(node.Value))
                Process(node);
            else
                Next?.Handle(node);
        }

        protected abstract bool CanHandle(object value);
        protected abstract void Process(ConfigurationNode node);
    }

    public class StringValueHandler : ValueHandlerBase
    {
        protected override bool CanHandle(object value) => value is string;
        protected override void Process(ConfigurationNode node)
        {
            if (node.Value is string s)
                node.Value = s.Trim();
        }
    }

    public class DictionaryValueHandler : ValueHandlerBase
    {
        protected override bool CanHandle(object value) => value is IDictionary<string, object>;
        protected override void Process(ConfigurationNode node)
        {
            if (node.Value is IDictionary<string, object> dict)
            {
                node.Children.AddRange(ConfigurationParser.ParseDictionary(dict, node.Path));
            }
        }
    }

    public interface IValueTransformationStrategy
    {
        object Transform(object value);
    }

    public class UppercaseStrategy : IValueTransformationStrategy
    {
        public object Transform(object value) => value is string s ? s.ToUpperInvariant() : value;
    }

    public class MultiplyStrategy : IValueTransformationStrategy
    {
        private readonly int _factor;
        public MultiplyStrategy(int factor) => _factor = factor;

        public object Transform(object value) => value is int i ? i * _factor : value;
    }

    public interface IConfigurationAction
    {
        void Execute(ConfigurationNode node);
    }

    public class ValidateCommand : IConfigurationAction
    {
        private readonly Func<ConfigurationNode, bool> _predicate;
        private readonly string _errorMessage;

        public ValidateCommand(Func<ConfigurationNode, bool> predicate, string errorMessage)
        {
            _predicate = predicate;
            _errorMessage = errorMessage;
        }

        public void Execute(ConfigurationNode node)
        {
            if (!_predicate(node))
                throw new InvalidOperationException($"Validation failed for {node.Path}: {_errorMessage}");
        }
    }

    public class TransformCommand : IConfigurationAction
    {
        private readonly IEnumerable<IValueTransformationStrategy> _strategies;

        public TransformCommand(IEnumerable<IValueTransformationStrategy> strategies)
        {
            _strategies = strategies;
        }

        public void Execute(ConfigurationNode node)
        {
            foreach (var strategy in _strategies)
                node.Value = strategy.Transform(node.Value);
        }
    }

    public class PersistCommand : IConfigurationAction
    {
        private readonly IDictionary<string, object> _store;

        public PersistCommand(IDictionary<string, object> store) => _store = store;

        public void Execute(ConfigurationNode node)
        {
            if (node.Children.Count == 0)
                _store[node.Path] = node.Value;
        }
    }

    public class ConfigurationActionVisitor
    {
        private readonly IEnumerable<IConfigurationAction> _actions;

        public ConfigurationActionVisitor(IEnumerable<IConfigurationAction> actions) => _actions = actions;

        public void Visit(ConfigurationNode node)
        {
            foreach (var action in _actions)
                action.Execute(node);
        }
    }

    public class ActionPlanBuilder
    {
        private readonly List<IConfigurationAction> _actions = new();

        public ActionPlanBuilder AddValidation(Func<ConfigurationNode, bool> predicate, string errorMessage)
        {
            _actions.Add(new ValidateCommand(predicate, errorMessage));
            return this;
        }

        public ActionPlanBuilder AddTransformation(params IValueTransformationStrategy[] strategies)
        {
            _actions.Add(new TransformCommand(strategies));
            return this;
        }

        public ActionPlanBuilder AddPersistence(IDictionary<string, object> store)
        {
            _actions.Add(new PersistCommand(store));
            return this;
        }

        public ConfigurationActionVisitor Build() => new(_actions);
    }

    public static class ConfigurationParser
    {
        public static IEnumerable<ConfigurationNode> ParseDictionary(
            IDictionary<string, object> dict,
            string prefix = "")
        {
            var nodes = new List<ConfigurationNode>();

            foreach (var kvp in dict)
            {
                var path = string.IsNullOrWhiteSpace(prefix) ? kvp.Key : $"{prefix}.{kvp.Key}";
                var node = new ConfigurationNode(path, kvp.Value);
                nodes.Add(node);

                if (kvp.Value is IDictionary<string, object> childDict)
                {
                    var children = ParseDictionary(childDict, path);
                    foreach (var child in children)
                        node.AddChild(child);
                }
            }

            return nodes;
        }

        public static ConfigurationNode BuildTree(IDictionary<string, object> flatInput)
        {
            var root = new ConfigurationNode("root", flatInput);
            foreach (var node in ParseDictionary(flatInput))
                root.AddChild(node);
            return root;
        }

        public static IReadOnlyList<ConfigurationNode> Flatten(ConfigurationNode root, bool includeRoot = false)
        {
            var flattened = new List<ConfigurationNode>();
            foreach (var node in new ConfigurationNodeIterator(root))
            {
                if (includeRoot || node != root)
                    flattened.Add(node);
            }
            return flattened;
        }
    }

    public class Program
    {
        public static void Main()
        {
            var input = new Dictionary<string, object>
            {
                ["database.connection.username"] = " admin ",
                ["database.connection.port"] = 5432,
                ["featureFlags"] = new Dictionary<string, object>
                {
                    ["beta"] = true,
                    ["maxUsers"] = 150
                }
            };

            var root = ConfigurationParser.BuildTree(input);

            var nodes = ConfigurationParser.Flatten(root); // flattened once, reused everywhere

            var stringHandler = new StringValueHandler();
            var dictHandler = new DictionaryValueHandler();
            stringHandler.SetNext(dictHandler);

            foreach (var node in nodes)
                stringHandler.Handle(node); // single enumeration

            var store = new Dictionary<string, object>();
            var plan = new ActionPlanBuilder()
                .AddValidation(node => node.Path != "database.connection.port" || (int)node.Value > 1024, "Port must be > 1024")
                .AddTransformation(new UppercaseStrategy(), new MultiplyStrategy(2))
                .AddPersistence(store)
                .Build();

            foreach (var node in nodes) // same flattened list reused
                plan.Visit(node);

            Console.WriteLine("Final persisted values:");
            foreach (var kvp in store)
                Console.WriteLine($"{kvp.Key} = {kvp.Value}");
        }
    }
}