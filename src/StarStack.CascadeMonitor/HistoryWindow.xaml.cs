using System.Windows;
using System.Windows.Media;
using System.Windows.Shapes;
using MediaColor = System.Windows.Media.Color;
using WpfPoint = System.Windows.Point;

namespace StarStack.CascadeMonitor;
public partial class HistoryWindow : Window
{
    private readonly HistoryStore _history;
    public HistoryWindow(HistoryStore history) { InitializeComponent(); _history = history; Loaded += (_, _) => Draw(); SizeChanged += (_, _) => Draw(); }
    private void Draw()
    {
        Chart.Children.Clear(); var rows = _history.Recent(); if (rows.Count < 2) { Summary.Text = "Пока недостаточно измерений"; return; }
        var load = new Polyline { Stroke = new SolidColorBrush(MediaColor.FromRgb(117,216,255)), StrokeThickness = 2 }; var ram = new Polyline { Stroke = new SolidColorBrush(MediaColor.FromRgb(255,173,92)), StrokeThickness = 2 }; var width = Math.Max(1, Chart.ActualWidth); var height = Math.Max(1, Chart.ActualHeight);
        for (var i = 0; i < rows.Count; i++) { var x = i * width / (rows.Count - 1); load.Points.Add(new WpfPoint(x, height - Math.Min(1, rows[i].Load) * height)); ram.Points.Add(new WpfPoint(x, height - Math.Min(100, rows[i].Ram) / 100 * height)); }
        Chart.Children.Add(load); Chart.Children.Add(ram); Summary.Text = $"Измерений: {rows.Count}";
    }
}
