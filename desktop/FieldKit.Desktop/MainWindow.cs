using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using Avalonia.Threading;
using FieldKit.Core;
using System.Globalization;
using System.Net;
using System.Text;

namespace FieldKit.Desktop;

public sealed class MainWindow : Window
{
    private sealed record Tool(string Id, string Name, string Description, string Icon);
    private static readonly Tool[] Tools = [
        new("networks", "My networks", "Every connection, in one place", "M4 4h6v6H4z M14 4h6v6h-6z M9 15h6v6H9z M7 10v3h10v-3 M12 13v2"),
        new("lan", "LAN devices", "Find devices and services on a local network", "M4 5h16v10H4z M8 20h8 M12 15v5"),
        new("ports", "Port scanner", "Check which TCP services answer", "M4 8h16v11H4z M8 8V4h8v4 M8 12v3 M12 12v3 M16 12v3"),
        new("ping", "Ping", "Measure reachability, latency and packet loss", "M3 12h4l3-8 4 16 3-8h4"),
        new("dns", "DNS lookup", "Ask a resolver for domain records", "M4 5h16v5H4z M4 14h16v5H4z M7 7.5h.1 M7 16.5h.1 M11 7.5h6 M11 16.5h6"),
        new("trace", "Traceroute", "Follow the path toward a destination", "M4 19V5h6v7h10 M17 9l3 3-3 3 M4 19h5"),
        new("rdap", "IP & domain info", "Look up public registration information", "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M3 12h18 M12 3c-4 4-4 14 0 18 M12 3c4 4 4 14 0 18"),
        new("wake", "Wake-on-LAN", "Send a wake packet to a configured device", "M12 3v9 M6 6a8 8 0 1 0 12 0"),
        new("wifi", "Wi-Fi signal", "Read available wireless information from the OS", "M3 8c5-5 13-5 18 0 M6 12c3-3 9-3 12 0 M9 16c2-2 4-2 6 0 M12 20h.01"),
        new("history", "Saved results", "Reopen results from earlier sessions", "M4 4v6h6 M4 9a9 9 0 1 1-1 6 M12 7v6l4 2"),
        new("settings", "Settings", "Appearance, storage and device capabilities", "M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6")
    ];
    private readonly UiSettings _settings = UiSettings.Load();
    private readonly ReportStore _store = new(UiSettings.DataDirectory);
    private IReadOnlyList<NetworkProfile> _networks = [];
    private readonly Dictionary<string, Report> _latest = new();
    private CancellationTokenSource? _operation;
    private string _tool = "networks";
    private int _navigation;
    private Report? _current;
    private Grid _shell = null!;
    private StackPanel _content = null!, _results = null!, _form = null!;
    private TextBlock _status = null!;
    private Button _run = null!, _stop = null!;
    private TextBox? _target, _extra, _filter;
    private ComboBox? _dnsType;
    private bool _dark;
    private bool _closing;
    private string? _activeTool;
    private IBrush Bg => Brush(_dark ? "#111822" : "#F3F6FA");
    private IBrush Surface => Brush(_dark ? "#1A2431" : "#FFFFFF");
    private IBrush Ink => Brush(_dark ? "#EDF3FB" : "#17293C");
    private IBrush Muted => Brush(_dark ? "#A6B5C7" : "#5F7185");
    private IBrush Line => Brush(_dark ? "#2C3A4C" : "#DFE7EF");
    private IBrush Accent => Brush(_dark ? "#7BAEFF" : "#245FC7");

    public MainWindow()
    {
        Title = "FieldKit · Network tools";
        Width = Math.Clamp(_settings.Width, 860, 2200);
        Height = Math.Clamp(_settings.Height, 620, 1600);
        MinWidth = 860; MinHeight = 620;
        FontFamily = new FontFamily("Inter, Segoe UI, sans-serif");
        FontSize = 14;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Icon = new WindowIcon(Avalonia.Platform.AssetLoader.Open(new Uri("avares://FieldKit/Assets/fieldkit.ico")));
        ApplyTheme();
        Opened += async (_, _) =>
        {
            try { _networks = await Analyzer.GetNetworksAsync(); }
            catch (Exception ex) { System.Diagnostics.Trace.WriteLine(ex); }
            await Navigate(Tools.Any(t => t.Id == _settings.Tool) ? _settings.Tool : "networks");
            if (Program.Arguments.Contains("--smoke-ui")) await SmokeUi();
        };
        Closing += async (_, e) =>
        {
            CaptureForm(); _settings.Tool = _tool; _settings.Width = Width; _settings.Height = Height; _settings.Save();
            if (_closing || _operation == null) return;
            e.Cancel = true; _closing = true; _operation.Cancel();
            if (_activeTool != null && _latest.TryGetValue(_activeTool, out var report)) await SaveQuietly(report);
            Close();
        };
        BuildShell();
    }

    private static SolidColorBrush Brush(string hex) => new(Color.Parse(hex));
    private void ApplyTheme()
    {
        var theme = _settings.Theme switch { "Dark" => ThemeVariant.Dark, "Light" => ThemeVariant.Light, _ => ThemeVariant.Default };
        if (Application.Current is { } app) app.RequestedThemeVariant = theme;
        RequestedThemeVariant = theme;
        _dark = _settings.Theme == "Dark" || (_settings.Theme == "System" && ActualThemeVariant == ThemeVariant.Dark);
    }

    private TextBlock Text(string text, double size = 14, IBrush? color = null, FontWeight? weight = null) => new()
    {
        Text = text, FontSize = size, Foreground = color ?? Ink, FontWeight = weight ?? FontWeight.Normal,
        TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center
    };
    private Border Card(Control child, Thickness? padding = null) => new()
    {
        Background = Surface, BorderBrush = Line, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12),
        Padding = padding ?? new Thickness(20), Child = child
    };
    private Button Button(string label, Action action, bool primary = false)
    {
        var button = new Button { Content = label, Padding = new Thickness(16, 10), CornerRadius = new CornerRadius(7), Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Hand), HorizontalContentAlignment = HorizontalAlignment.Center };
        if (primary) { button.Background = Brush(_dark ? "#3268CC" : "#245FC7"); button.Foreground = Brush("#FFFFFF"); }
        button.Click += (_, _) => action();
        return button;
    }
    private static StackPanel Stack(params Control[] controls) { var stack = new StackPanel { Spacing = 10 }; foreach (var c in controls) stack.Children.Add(c); return stack; }
    private static StackPanel Row(params Control[] controls) { var row = Stack(controls); row.Orientation = Orientation.Horizontal; row.VerticalAlignment = VerticalAlignment.Center; return row; }
    private Control DrawIcon(string data, IBrush color) => new Viewbox
    {
        Width = 22, Height = 22,
        Child = new Avalonia.Controls.Shapes.Path { Width = 24, Height = 24, Data = Geometry.Parse(data), Stroke = color, StrokeThickness = 1.7, StrokeLineCap = PenLineCap.Round, StrokeJoin = PenLineJoin.Round }
    };

    private void BuildShell()
    {
        Background = Bg;
        _shell = new Grid { ColumnDefinitions = new ColumnDefinitions("214,*") };
        var sidebar = new DockPanel { LastChildFill = true, Margin = new Thickness(18, 24, 14, 18) };
        var brand = Stack(Text("FIELDKIT", 23, Ink, FontWeight.Bold), Text("NETWORK TOOLS", 10, Muted, FontWeight.SemiBold));
        brand.Margin = new Thickness(12, 0, 0, 28); DockPanel.SetDock(brand, Dock.Top); sidebar.Children.Add(brand);
        var bottom = Stack(Text("VERSION 1.0", 11, Muted, FontWeight.SemiBold), Text("Saved locally. No account needed.", 11, Muted));
        bottom.Margin = new Thickness(12, 18, 6, 0); DockPanel.SetDock(bottom, Dock.Bottom); sidebar.Children.Add(bottom);
        var navigation = new StackPanel { Spacing = 4 };
        foreach (var item in Tools)
        {
            if (item.Id == "history") navigation.Children.Add(new Border { Height = 18 });
            var selected = item.Id == _tool;
            var label = Row(DrawIcon(item.Icon, selected ? Accent : Muted), Text(item.Name, 13, selected ? Accent : Ink, selected ? FontWeight.SemiBold : FontWeight.Normal));
            label.Spacing = 12;
            var button = new Button { Content = label, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left, Background = selected ? Brush(_dark ? "#253C59" : "#E5EEFC") : Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(12, 11), CornerRadius = new CornerRadius(8) };
            button.Click += async (_, _) => await Navigate(item.Id);
            navigation.Children.Add(button);
        }
        sidebar.Children.Add(new ScrollViewer { Content = navigation, VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto });
        _shell.Children.Add(sidebar);
        _content = new StackPanel { Spacing = 18, Margin = new Thickness(26, 28, 30, 28) };
        var scroll = new ScrollViewer { Content = _content, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
        Grid.SetColumn(scroll, 1); _shell.Children.Add(scroll); Content = _shell;
    }

    private void CaptureForm()
    {
        if (_target != null) _settings.Targets[_tool] = _target.Text ?? "";
        if (_extra != null) _settings.Extras[_tool] = _extra.Text ?? "";
    }
    private async Task Navigate(string tool)
    {
        CaptureForm(); _tool = tool; _settings.Tool = tool; _settings.Save();
        var generation = ++_navigation; _target = null; _extra = null; _filter = null; _current = null;
        BuildShell();
        var definition = Tools.First(t => t.Id == tool);
        _content.Children.Add(Stack(Text(definition.Name, 30, Ink, FontWeight.SemiBold), Text(definition.Description, 14, Muted)));
        if (tool == "settings") { ShowSettings(); return; }
        if (tool == "history") { await ShowHistory(generation); return; }
        if (tool == "networks") { ShowNetworks(); return; }
        BuildToolForm(tool);
        _results = new StackPanel { Spacing = 12 };
        _content.Children.Add(_results);
        if (_latest.TryGetValue(tool, out var saved)) ShowReport(saved, true);
        else
        {
            ShowEmpty("Your results will appear here", "Run a check when you need it. The latest results stay available after you close FieldKit.");
            try
            {
                var report = await _store.LoadLatestAsync(tool);
                if (generation == _navigation && report != null) { _latest[tool] = report; ShowReport(report, true); }
            }
            catch (Exception ex) { if (generation == _navigation) _status.Text = "Saved results could not be opened: " + ex.Message; }
        }
    }

    private void ShowNetworks()
    {
        var bar = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        bar.Children.Add(Text($"{_networks.Count} network interfaces · addresses are kept separate", 13, Muted));
        var refresh = Button("Refresh networks", async () => { try { _networks = await Analyzer.GetNetworksAsync(); await Navigate("networks"); } catch (Exception ex) { await Notice("Could not refresh", ex.Message); } });
        Grid.SetColumn(refresh, 1); bar.Children.Add(refresh); _content.Children.Add(bar);
        if (_networks.Count == 0) _content.Children.Add(Card(Stack(Text("No network interfaces found", 18, Ink, FontWeight.SemiBold), Text("Connect to Wi-Fi, Ethernet or a VPN, then refresh.", 13, Muted))));
        var active = _networks.Where(n => n.Status.Equals("Up", StringComparison.OrdinalIgnoreCase) && n.Addresses.Count > 0 && n.Kind != "Loopback").ToList();
        var other = new StackPanel { Spacing = 12 };
        foreach (var network in _networks.OrderByDescending(n => n.Status.Equals("Up", StringComparison.OrdinalIgnoreCase)).ThenBy(n => n.Name))
        {
            var top = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
            top.Children.Add(Stack(Text(network.Name, 18, Ink, FontWeight.SemiBold), Text(network.Description, 12, Muted)));
            var tags = Row(Badge(network.Kind), Badge(network.Status, network.Status.Equals("Up", StringComparison.OrdinalIgnoreCase) ? "green" : "gray")); Grid.SetColumn(tags, 1); top.Children.Add(tags);
            var addresses = new StackPanel { Spacing = 7 };
            foreach (var a in network.Addresses)
            {
                var line = new Grid { ColumnDefinitions = new ColumnDefinitions("64,*,Auto") };
                line.Children.Add(Text(a.Family, 11, Muted, FontWeight.SemiBold));
                var address = Text(a.Cidr, 14); address.FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace"); Grid.SetColumn(address, 1); line.Children.Add(address);
                if (IPAddress.TryParse(a.Address.Split('%')[0], out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var use = Button("Scan LAN", async () => { _settings.Targets["lan"] = a.Cidr; await Navigate("lan"); }); use.Padding = new Thickness(12, 5); Grid.SetColumn(use, 2); line.Children.Add(use);
                }
                addresses.Children.Add(line);
            }
            if (network.Addresses.Count == 0) addresses.Children.Add(Text("No assigned addresses", 13, Muted));
            var details = new List<string>();
            if (network.Gateways.Count > 0) details.Add("Gateway  " + string.Join(", ", network.Gateways));
            if (network.DnsServers.Count > 0) details.Add("DNS  " + string.Join(", ", network.DnsServers));
            if (!string.IsNullOrWhiteSpace(network.Mac)) details.Add("MAC  " + network.Mac);
            var card = Card(Stack(top, addresses, Text(string.Join("\n", details), 12, Muted)));
            if (active.Contains(network)) _content.Children.Add(card); else other.Children.Add(card);
        }
        if (other.Children.Count > 0) _content.Children.Add(new Expander { Header = $"Other adapters · {other.Children.Count}", Content = other, HorizontalAlignment = HorizontalAlignment.Stretch });
        _content.Children.Add(Text("Tools use your operating system’s routing, including VPN policies. A connected interface does not guarantee access to every device on that network.", 12, Muted));
    }

    private void BuildToolForm(string tool)
    {
        _form = new StackPanel { Spacing = 12 };
        if (tool != "wifi")
        {
            var labels = tool switch { "lan" => ("Network or device", "192.168.1.0/24"), "wake" => ("Device MAC address", "AA:BB:CC:DD:EE:FF"), "rdap" => ("Public IP address or domain", "example.com"), _ => ("Host or IP address", "192.168.1.1 or example.com") };
            _target = new TextBox { Text = _settings.Targets.GetValueOrDefault(tool, DefaultTarget(tool)), Watermark = labels.Item2, MinWidth = 200 };
            _target.TextChanged += (_, _) => { _settings.Targets[tool] = _target.Text ?? ""; };
            _form.Children.Add(Stack(Text(labels.Item1, 12, Muted, FontWeight.SemiBold), _target));
            if (tool is not "wake" and not "rdap")
            {
                var suggestions = Suggestions(tool).ToArray();
                if (suggestions.Length > 0)
                {
                    var choices = new ComboBox { PlaceholderText = "Use a connected network or discovered address…", ItemsSource = suggestions, HorizontalAlignment = HorizontalAlignment.Stretch, MaxDropDownHeight = 280 };
                    choices.SelectionChanged += (_, _) => { if (choices.SelectedItem is Suggestion suggestion && _target != null) _target.Text = suggestion.Target; };
                    _form.Children.Add(choices);
                }
            }
        }
        if (tool is "lan" or "ports")
        {
            _extra = new TextBox { Text = _settings.Extras.GetValueOrDefault(tool, tool == "lan" ? "22,53,80,139,443,445,3389,8080" : Analyzer.CommonPorts), Watermark = "22,80,443 or 1-1024" };
            var targetField = _form.Children[0]; _form.Children.RemoveAt(0);
            var fields = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*"), ColumnSpacing = 14 };
            fields.Children.Add(targetField);
            var portsField = Stack(Text("TCP ports", 12, Muted, FontWeight.SemiBold), _extra); Grid.SetColumn(portsField, 1); fields.Children.Add(portsField); _form.Children.Insert(0, fields);
        }
        if (tool == "dns")
        {
            _dnsType = new ComboBox { ItemsSource = new[] { "A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SOA", "SRV" }, SelectedIndex = 0, MinWidth = 100 };
            _extra = new TextBox { Text = _settings.Extras.GetValueOrDefault(tool, ""), Watermark = "OS default resolver", MinWidth = 200, HorizontalAlignment = HorizontalAlignment.Stretch };
            var dnsGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("120,*"), ColumnSpacing = 12 };
            dnsGrid.Children.Add(Stack(Text("Record type", 12, Muted, FontWeight.SemiBold), _dnsType));
            var server = Stack(Text("DNS server · optional IP", 12, Muted, FontWeight.SemiBold), _extra); Grid.SetColumn(server, 1); dnsGrid.Children.Add(server); _form.Children.Add(dnsGrid);
        }
        if (tool == "wake")
        {
            _extra = new TextBox { Text = _settings.Extras.GetValueOrDefault(tool, "255.255.255.255"), Watermark = "255.255.255.255" };
            _form.Children.Add(Stack(Text("Broadcast address", 12, Muted, FontWeight.SemiBold), _extra));
            _form.Children.Add(Text("The destination needs Wake-on-LAN enabled in its firmware and network adapter. A sent packet does not confirm that the device woke up.", 12, Muted));
        }
        if (tool == "wifi") _form.Children.Add(Text("Wireless details depend on operating system access and available drivers. This view does not start Bluetooth discovery or UWB ranging.", 13, Muted));
        _run = Button(tool switch { "lan" => "Scan network", "ports" => "Scan ports", "dns" => "Look up records", "wake" => "Send wake packet", "wifi" => "Read signal", "rdap" => "Look up information", _ => "Start check" }, async () => await RunTool(), true);
        _stop = Button("Stop", () => _operation?.Cancel()); _stop.IsVisible = _operation != null;
        _run.IsEnabled = _operation == null;
        _status = Text(_operation == null ? "Ready when you are" : "A check is running. Stop it before starting another.", 12, Muted);
        _form.Children.Add(Row(_run, _stop)); _form.Children.Add(_status);
        _content.Children.Add(Card(_form));
    }

    private string DefaultTarget(string tool)
    {
        if (tool == "lan") return _networks.Where(n => n.Status == "Up").OrderBy(n => n.Kind == "Wi-Fi" ? 0 : n.Kind == "Ethernet" ? 1 : 2).SelectMany(n => n.Addresses).FirstOrDefault(a => a.Family.Contains('4') && !a.Address.StartsWith("127."))?.Cidr ?? "";
        if (tool == "wake") return "";
        if (tool is "dns" or "rdap" or "ping" or "trace") return "example.com";
        return _networks.SelectMany(n => n.Gateways).FirstOrDefault(g => g.Contains('.')) ?? "";
    }
    private sealed record Suggestion(string Label, string Target) { public override string ToString() => Label; }
    private IEnumerable<Suggestion> Suggestions(string tool)
    {
        foreach (var n in _networks)
        {
            foreach (var a in n.Addresses.Where(a => tool != "lan" || a.Family.Contains('4')))
                yield return new Suggestion($"{n.Name} · {n.Kind} · {(tool == "lan" ? a.Cidr : a.Address)}", tool == "lan" ? a.Cidr : a.Address);
            if (tool != "lan") foreach (var gateway in n.Gateways) yield return new Suggestion($"{n.Name} gateway · {gateway}", gateway);
        }
        if (tool != "lan" && _latest.TryGetValue("lan", out var report))
            foreach (var r in report.Rows.Where(r => r.Count > 1).Take(128)) yield return new Suggestion($"{(r[0] is "" or "—" ? "Discovered device" : r[0])} · {r[1]}", r[1]);
    }

    private async Task RunTool()
    {
        if (_operation != null) return;
        CaptureForm(); _settings.Save();
        var tool = _tool; var target = _target?.Text?.Trim() ?? ""; var extra = _extra?.Text?.Trim() ?? "";
        var dnsType = _dnsType?.SelectedItem?.ToString() ?? "A";
        if (tool != "wifi" && string.IsNullOrWhiteSpace(target)) { _status.Text = "Enter a target to continue."; _target?.Focus(); return; }
        _operation = new CancellationTokenSource(); _activeTool = tool; var cancellation = _operation;
        _run.IsEnabled = false; _stop.IsVisible = true; _status.Text = "Checking… Results appear as they arrive.";
        var progress = new Progress<Report>(report => { _latest[tool] = report; if (_tool == tool) ShowReport(report, false); });
        try
        {
            var report = tool switch
            {
                "lan" => await Analyzer.ScanLanAsync(new LanScanOptions(target, extra), cancellation.Token, progress),
                "ports" => await Analyzer.ScanPortsAsync(new PortScanOptions(target, extra), cancellation.Token, progress),
                "ping" => await Analyzer.PingAsync(new PingOptions(target), cancellation.Token, progress),
                "dns" => await Analyzer.DnsAsync(new DnsOptions(target, dnsType, string.IsNullOrEmpty(extra) ? null : extra), cancellation.Token),
                "trace" => await Analyzer.TraceAsync(new TraceOptions(target), cancellation.Token),
                "rdap" => await Analyzer.RdapAsync(target, cancellation.Token),
                "wake" => await Analyzer.WakeAsync(new WakeOptions(target, extra), cancellation.Token),
                "wifi" => await Analyzer.WifiAsync(cancellation.Token),
                _ => throw new InvalidOperationException("This check is unavailable.")
            };
            _latest[tool] = report; await _store.SaveAsync(report);
            if (_tool == tool) { ShowReport(report, false); _status.Text = "Complete · result saved on this computer"; }
        }
        catch (OperationCanceledException)
        {
            if (_latest.TryGetValue(tool, out var partial)) await SaveQuietly(partial);
            if (_tool == tool) _status.Text = "Stopped · any results already received are kept";
        }
        catch (Exception ex) { if (_tool == tool) _status.Text = "Could not complete: " + ex.Message; }
        finally
        {
            cancellation.Dispose(); _operation = null; _activeTool = null;
            if (_tool is not "networks" and not "settings" and not "history") { _run.IsEnabled = true; _stop.IsVisible = false; }
        }
    }
    private async Task SaveQuietly(Report report) { try { await _store.SaveAsync(report); } catch (Exception ex) { System.Diagnostics.Trace.WriteLine(ex); } }

    private void ShowEmpty(string title, string description) => _results.Children.Add(Card(Stack(Text(title, 18, Ink, FontWeight.SemiBold), Text(description, 13, Muted)), new Thickness(24, 30)));
    private void ShowReport(Report report, bool restored)
    {
        _current = report; _results.Children.Clear();
        var title = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        var when = report.CreatedAt.ToLocalTime().ToString("dd MMM yyyy · HH:mm:ss", CultureInfo.CurrentCulture);
        title.Children.Add(Stack(Text(report.Title, 20, Ink, FontWeight.SemiBold), Text($"{(restored ? "Saved observation" : "Observed")} · {when} · {report.Rows.Count} {(report.Rows.Count == 1 ? "result" : "results")}", 12, Muted)));
        var export = Button("Export…", async () => await Export(report)); Grid.SetColumn(export, 1); title.Children.Add(export); _results.Children.Add(title);
        if (report.Summary.Count > 0)
        {
            var summary = Stack(Text(report.Summary[0], 13, Ink, FontWeight.SemiBold));
            if (report.Summary.Count > 1) summary.Children.Add(new Expander { Header = "Source & interpretation", Content = Stack(report.Summary.Skip(1).Select(s => Text(s, 12, Muted)).ToArray()), Padding = new Thickness(0), HorizontalAlignment = HorizontalAlignment.Stretch });
            _results.Children.Add(Card(summary, new Thickness(14, 10)));
        }
        if (report.Tool == "lan")
        {
            var legend = new WrapPanel { Orientation = Orientation.Horizontal, ItemSpacing = 8, LineSpacing = 6 };
            foreach (var (name, kind) in new[] { ("IPv4", "blue"), ("IPv6", "purple"), ("Gateway", "orange"), ("This computer", "gray"), ("Open TCP port", "green"), ("Service advertised", "purple") }) legend.Children.Add(Badge(name, kind));
            _results.Children.Add(Stack(legend, Text("Tags show observed facts. Bluetooth, device type and unobserved IPv6 support remain unknown.", 11, Muted)));
        }
        if (report.Rows.Count == 0) { ShowEmpty("No results to show", "Check the target, connection and permissions, then try again. Devices may ignore discovery probes."); return; }
        _filter = new TextBox { Watermark = "Filter these results…" };
        var rowsPanel = new StackPanel { Spacing = report.Tool == "lan" ? 8 : 0 };
        void RenderRows()
        {
            rowsPanel.Children.Clear(); var query = _filter.Text?.Trim() ?? "";
            var rows = report.Rows.Where(r => string.IsNullOrEmpty(query) || r.Any(s => s.Contains(query, StringComparison.OrdinalIgnoreCase))).ToList();
            if (report.Tool == "lan") foreach (var r in rows) rowsPanel.Children.Add(DeviceCard(report, r));
            else rowsPanel.Children.Add(ResultTable(report, rows));
            if (rows.Count == 0) rowsPanel.Children.Add(Text("No results match your filter.", 13, Muted));
        }
        _filter.TextChanged += (_, _) => RenderRows(); _results.Children.Add(_filter); RenderRows(); _results.Children.Add(rowsPanel);
    }

    private Control DeviceCard(Report report, List<string> row)
    {
        string Cell(int index) => index < row.Count ? row[index] : "";
        var address = Cell(1); var name = Cell(0);
        if (string.IsNullOrWhiteSpace(name) || name is "—" or "Unknown" or "Unnamed") name = "Unnamed device";
        var body = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 12 };
        var details = Stack(Text(name, 16, Ink, FontWeight.SemiBold), Text(address, 13, Muted)); details.Spacing = 4;
        var ports = Cell(3); var capabilities = Cell(2);
        var hasOpen = capabilities.Contains("TCP open", StringComparison.OrdinalIgnoreCase);
        if (hasOpen) details.Children.Add(Text("Open TCP ports  " + ports, 12, Muted));
        else details.Children.Add(Text("No open TCP ports confirmed", 12, Muted));
        body.Children.Add(details);
        var right = new StackPanel { Spacing = 7, HorizontalAlignment = HorizontalAlignment.Right };
        var tags = new WrapPanel { MaxWidth = 260, ItemSpacing = 5, LineSpacing = 5, HorizontalAlignment = HorizontalAlignment.Right };
        if (IPAddress.TryParse(address.Split('%')[0], out var ip)) tags.Children.Add(Badge(ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "IPv4" : "IPv6", ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "blue" : "purple"));
        if (capabilities.Contains("gateway", StringComparison.OrdinalIgnoreCase)) tags.Children.Add(Badge("Gateway", "orange"));
        if (capabilities.Contains("self", StringComparison.OrdinalIgnoreCase) || capabilities.Contains("this", StringComparison.OrdinalIgnoreCase)) tags.Children.Add(Badge("This computer", "gray"));
        if (hasOpen) tags.Children.Add(Badge("Open TCP port", "green"));
        if (capabilities.Contains("Service advertised", StringComparison.OrdinalIgnoreCase)) tags.Children.Add(Badge("Service advertised", "purple"));
        right.Children.Add(tags);
        var actions = Row(Button("Ports", async () => { _settings.Targets["ports"] = address; await Navigate("ports"); }), Button("Details", async () => await ShowDetails(report, row)));
        foreach (var action in actions.Children.OfType<Button>()) action.Padding = new Thickness(10, 4);
        right.Children.Add(actions); Grid.SetColumn(right, 1); body.Children.Add(right);
        return Card(body, new Thickness(16, 13));
    }

    private Control ResultTable(Report report, List<List<string>> rows)
    {
        var table = new StackPanel { Spacing = 0, MinWidth = Math.Min(900, Math.Max(520, report.Columns.Count * 140)) };
        Grid MakeRow(IReadOnlyList<string> cells, bool header)
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(string.Join(",", Enumerable.Repeat("*", report.Columns.Count))), ColumnSpacing = 16 };
            for (var i = 0; i < report.Columns.Count; i++)
            {
                var text = Text(i < cells.Count && !string.IsNullOrWhiteSpace(cells[i]) ? cells[i] : "—", header ? 11 : 13, header ? Muted : Ink, header ? FontWeight.SemiBold : FontWeight.Normal);
                text.VerticalAlignment = VerticalAlignment.Top; Grid.SetColumn(text, i); grid.Children.Add(text);
            }
            return grid;
        }
        table.Children.Add(new Border { Background = Bg, Padding = new Thickness(16, 12), Child = MakeRow(report.Columns, true) });
        foreach (var row in rows) table.Children.Add(new Border { BorderBrush = Line, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(16, 14), Child = MakeRow(row, false) });
        return Card(new ScrollViewer { Content = table, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto, VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled }, new Thickness(0));
    }

    private Border Badge(string label, string kind = "blue")
    {
        var colors = kind switch
        {
            "green" => (_dark ? "#173F36" : "#E5F4ED", _dark ? "#87D7B7" : "#1C7150"),
            "orange" => (_dark ? "#493821" : "#FFF0DA", _dark ? "#F5C77D" : "#8D560C"),
            "purple" => (_dark ? "#3A2D52" : "#F0E9FB", _dark ? "#C9AAEE" : "#6D42A3"),
            "gray" => (_dark ? "#303C4B" : "#EDF1F5", _dark ? "#C1CBD8" : "#52677A"),
            _ => (_dark ? "#233D5E" : "#E7EFFC", _dark ? "#A4C7FF" : "#275CAC")
        };
        return new Border { Background = Brush(colors.Item1), CornerRadius = new CornerRadius(5), Padding = new Thickness(8, 4), Child = Text(label, 10, Brush(colors.Item2), FontWeight.SemiBold) };
    }

    private async Task ShowDetails(Report report, List<string> row)
    {
        var details = new StackPanel { Spacing = 16 };
        for (var i = 0; i < report.Columns.Count; i++) details.Children.Add(Stack(Text(report.Columns[i], 11, Muted, FontWeight.SemiBold), Text(i < row.Count && !string.IsNullOrWhiteSpace(row[i]) ? row[i] : "Unavailable", 14)));
        await Notice("Device details", details);
    }
    private Task Notice(string title, string message) => Notice(title, Text(message, 14));
    private async Task Notice(string title, Control content)
    {
        var dialog = new Window { Title = title, Width = 600, Height = 520, MinWidth = 400, MinHeight = 280, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Bg, RequestedThemeVariant = RequestedThemeVariant };
        var close = Button("Close", () => dialog.Close()); close.HorizontalAlignment = HorizontalAlignment.Right;
        var panel = new DockPanel { Margin = new Thickness(24), LastChildFill = true }; DockPanel.SetDock(close, Dock.Bottom); panel.Children.Add(close);
        var header = Text(title, 22, Ink, FontWeight.SemiBold); header.Margin = new Thickness(0, 0, 0, 18); DockPanel.SetDock(header, Dock.Top); panel.Children.Add(header);
        panel.Children.Add(new ScrollViewer { Content = content }); dialog.Content = panel; await dialog.ShowDialog(this);
    }

    private async Task Export(Report report)
    {
        try
        {
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Export result", SuggestedFileName = $"FieldKit-{report.Tool}-{report.CreatedAt:yyyyMMdd-HHmmss}.csv", DefaultExtension = "csv", FileTypeChoices = [new FilePickerFileType("CSV table") { Patterns = ["*.csv"] }, new FilePickerFileType("JSON report") { Patterns = ["*.json"] }], ShowOverwritePrompt = true });
            if (file == null) return;
            await using var stream = await file.OpenWriteAsync(); stream.SetLength(0);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(true));
            await writer.WriteAsync(file.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? ReportStore.ExportJson(report) : ReportStore.ExportCsv(report));
            if (_status != null) _status.Text = "Exported " + file.Name;
        }
        catch (Exception ex) { await Notice("Export could not finish", ex.Message); }
    }

    private async Task ShowHistory(int generation)
    {
        _content.Children.Add(Text("Results are stored on this computer. Reopening a saved result sends no new probes.", 13, Muted));
        try
        {
            var reports = await _store.LoadHistoryAsync(); if (_navigation != generation) return;
            if (reports.Count == 0) { _content.Children.Add(Card(Stack(Text("No saved results yet", 18, Ink, FontWeight.SemiBold), Text("Run a network check and it will appear here.", 13, Muted)))); return; }
            foreach (var report in reports.Take(100))
            {
                var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = 16 };
                grid.Children.Add(Stack(Text(report.Title, 16, Ink, FontWeight.SemiBold), Text($"{report.CreatedAt.ToLocalTime():dd MMM yyyy · HH:mm} · {report.Rows.Count} results", 12, Muted)));
                var open = Button("Open result", async () => { if (!Tools.Any(t => t.Id == report.Tool)) { await Notice(report.Title, string.Join("\n", report.Summary)); return; } _latest[report.Tool] = report; await Navigate(report.Tool); }); Grid.SetColumn(open, 1); grid.Children.Add(open); _content.Children.Add(Card(grid, new Thickness(16)));
            }
        }
        catch (Exception ex) { if (_navigation == generation) _content.Children.Add(Text("Could not open saved results: " + ex.Message, 13, Muted)); }
    }

    private void ShowSettings()
    {
        var appearance = new ComboBox { ItemsSource = new[] { "System", "Light", "Dark" }, SelectedItem = _settings.Theme, Width = 200 };
        appearance.SelectionChanged += async (_, _) => { if (appearance.SelectedItem is string theme) { _settings.Theme = theme; _settings.Save(); ApplyTheme(); await Navigate("settings"); } };
        _content.Children.Add(Card(Stack(Text("Appearance", 18, Ink, FontWeight.SemiBold), Text("Use your desktop preference, or choose a fixed theme.", 13, Muted), appearance)));
        _content.Children.Add(Card(Stack(Text("Kept on this computer", 18, Ink, FontWeight.SemiBold), Text("The latest results, earlier checks, form entries and theme survive closing the app. Saved observations keep their original time and are never presented as live readings.", 13, Muted), Text(UiSettings.DataDirectory, 12, Muted))));
        _content.Children.Add(Card(Stack(Text("Nearby & precision finding", 18, Ink, FontWeight.SemiBold), Badge("Not available in desktop 1.0", "gray"), Text("This release does not implement Bluetooth discovery, Wi-Fi RTT distance or UWB pairing on Windows/Linux. Hardware presence alone does not enable these functions. Use FieldKit for Android for signal finding and supported phone-to-phone UWB sessions.", 13, Muted), Text("A compass cannot locate a device from its IP address. No distance or directional arrow is simulated.", 12, Muted))));
        _content.Children.Add(Card(Stack(Text("FieldKit 1.0", 18, Ink, FontWeight.SemiBold), Text("A practical toolkit for network inventory, LAN devices, TCP ports, ping, DNS, traceroute, registration information and Wake-on-LAN.", 13, Muted), Text("Checks run only when you start them. FieldKit has no telemetry or account service. Public registration lookups contact external RDAP services; other tools contact the target or resolver you choose.", 12, Muted))));
    }

    private async Task SmokeUi()
    {
        try
        {
            var args = Program.Arguments;
            var screenshotIndex = Array.IndexOf(args, "--screenshot");
            var screenshot = screenshotIndex >= 0 && screenshotIndex + 1 < args.Length ? System.IO.Path.GetFullPath(args[screenshotIndex + 1]) : null;
            foreach (var tool in Tools)
            {
                await Navigate(tool.Id);
                await Task.Delay(70);
                if (_content.Bounds.Width <= 0 || _content.Bounds.Height <= 0) throw new InvalidOperationException($"The {tool.Id} view did not lay out.");
            }
            var viewIndex = Array.IndexOf(args, "--smoke-view");
            var view = viewIndex >= 0 && viewIndex + 1 < args.Length ? args[viewIndex + 1] : "networks";
            if (!Tools.Any(t => t.Id == view)) throw new ArgumentException("Unknown --smoke-view.");
            await Navigate(view); await Task.Delay(250);
            if (screenshot != null)
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(screenshot)!);
                using var bitmap = new RenderTargetBitmap(new PixelSize((int)Math.Ceiling(Bounds.Width), (int)Math.Ceiling(Bounds.Height)), new Vector(96, 96));
                bitmap.Render(this); bitmap.Save(screenshot);
            }
            Console.WriteLine($"FieldKit UI smoke passed: {Tools.Length} views initialized; {Bounds.Width}×{Bounds.Height} client area.");
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(0);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.Shutdown(1);
        }
    }
}
