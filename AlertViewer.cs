using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BWP.Enterprise.Agent.Core;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Storage;
using LiveCharts;
using LiveCharts.Wpf;
using LiveCharts.Configurations;

namespace BWP.Enterprise.Agent.UI
{
    /// <summary>
    /// Lógica de interacción para AlertViewer.xaml
    /// </summary>
    public partial class AlertViewer : Window
    {
        private readonly LogManager _logManager;
        private readonly LocalDatabase _localDatabase;
        private readonly ModuleRegistry _moduleRegistry;
        
        public AlertViewer()
        {
            InitializeComponent();
            
            _logManager = LogManager.Instance;
            _localDatabase = LocalDatabase.Instance;
            _moduleRegistry = ModuleRegistry.Instance;
            
            DataContext = new AlertViewModel();
            Loaded += OnLoaded;
        }
        
        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            await LoadAlertsAsync();
            SetupCharts();
        }
        
        private async Task LoadAlertsAsync()
        {
            try
            {
                var viewModel = (AlertViewModel)DataContext;
                viewModel.IsLoading = true;
                
                // Cargar alertas de la base de datos
                var alerts = await _localDatabase.GetRecentAlertsAsync(
                    Environment.MachineName, 
                    TimeSpan.FromDays(7));
                
                viewModel.Alerts = new ObservableCollection<SecurityAlert>(alerts);
                viewModel.TotalAlerts = alerts.Count;
                viewModel.CriticalAlerts = alerts.Count(a => a.Severity == ThreatSeverity.Critical);
                viewModel.HighAlerts = alerts.Count(a => a.Severity == ThreatSeverity.High);
                viewModel.MediumAlerts = alerts.Count(a => a.Severity == ThreatSeverity.Medium);
                viewModel.LowAlerts = alerts.Count(a => a.Severity == ThreatSeverity.Low);
                
                // Agrupar por tipo para el gráfico
                viewModel.UpdateChartData(alerts);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar alertas: {ex}", nameof(AlertViewer));
                MessageBox.Show($"Error al cargar alertas: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                var viewModel = (AlertViewModel)DataContext;
                viewModel.IsLoading = false;
            }
        }
        
        private void SetupCharts()
        {
            var viewModel = (AlertViewModel)DataContext;
            
            // Configurar gráfico de severidad
            SeverityChart.Series = viewModel.SeveritySeries;
            SeverityChart.LegendLocation = LegendLocation.Right;
            
            // Configurar gráfico de tendencia temporal
            var dayConfig = Mappers.Xy<DateValue>()
                .X(dayModel => (double)dayModel.DateTime.Ticks / TimeSpan.FromDays(1).Ticks)
                .Y(dayModel => dayModel.Value);
                
            TrendChart.Series = viewModel.TrendSeries;
            TrendChart.AxisX.Add(new Axis
            {
                LabelFormatter = value => new DateTime((long)(value * TimeSpan.FromDays(1).Ticks)).ToString("MM/dd"),
                Separator = new Separator { Step = TimeSpan.FromDays(1).Ticks / TimeSpan.FromDays(1).Ticks }
            });
        }
        
        private async void OnRefreshClick(object sender, RoutedEventArgs e)
        {
            await LoadAlertsAsync();
        }
        
        private async void OnExportClick(object sender, RoutedEventArgs e)
        {
            try
            {
                var viewModel = (AlertViewModel)DataContext;
                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "JSON files (*.json)|*.json|CSV files (*.csv)|*.csv",
                    DefaultExt = ".json",
                    FileName = $"bwp-alerts-{DateTime.Now:yyyyMMdd-HHmmss}"
                };
                
                if (dialog.ShowDialog() == true)
                {
                    await viewModel.ExportAlertsAsync(dialog.FileName);
                    MessageBox.Show($"Alertas exportadas exitosamente a {dialog.FileName}", 
                        "Éxito", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al exportar alertas: {ex}", nameof(AlertViewer));
                MessageBox.Show($"Error al exportar alertas: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void OnAlertSelected(object sender, SelectionChangedEventArgs e)
        {
            if (e.AddedItems.Count > 0 && e.AddedItems[0] is SecurityAlert selectedAlert)
            {
                var viewModel = (AlertViewModel)DataContext;
                viewModel.SelectedAlert = selectedAlert;
                
                // Mostrar detalles del alerta
                ShowAlertDetails(selectedAlert);
            }
        }
        
        private void ShowAlertDetails(SecurityAlert alert)
        {
            DetailsPanel.Visibility = Visibility.Visible;
            
            // Mostrar información detallada del alerta
            AlertTitle.Text = alert.Title;
            AlertSeverity.Text = alert.Severity.ToString();
            AlertSeverity.Foreground = GetSeverityColor(alert.Severity);
            AlertTime.Text = alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
            AlertSource.Text = alert.Source;
            AlertStatus.Text = alert.Status.ToString();
            AlertDetails.Text = alert.Details;
            
            // Mostrar acciones recomendadas si están disponibles
            if (alert.RecommendedActions != null && alert.RecommendedActions.Any())
            {
                RecommendedActions.ItemsSource = alert.RecommendedActions;
            }
            else
            {
                RecommendedActions.ItemsSource = new[] { "Investigar manualmente", "Monitorear actividad" };
            }
        }
        
        private Brush GetSeverityColor(ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Critical => new SolidColorBrush(Colors.Red),
                ThreatSeverity.High => new SolidColorBrush(Colors.Orange),
                ThreatSeverity.Medium => new SolidColorBrush(Colors.Yellow),
                ThreatSeverity.Low => new SolidColorBrush(Colors.LightBlue),
                _ => new SolidColorBrush(Colors.Gray)
            };
        }
        
        private async void OnAcknowledgeClick(object sender, RoutedEventArgs e)
        {
            var viewModel = (AlertViewModel)DataContext;
            if (viewModel.SelectedAlert != null)
            {
                try
                {
                    await viewModel.AcknowledgeAlertAsync(viewModel.SelectedAlert.AlertId);
                    MessageBox.Show("Alerta marcada como reconocida", "Éxito", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    await LoadAlertsAsync();
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al reconocer alerta: {ex}", nameof(AlertViewer));
                    MessageBox.Show($"Error: {ex.Message}", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        
        private async void OnResolveClick(object sender, RoutedEventArgs e)
        {
            var viewModel = (AlertViewModel)DataContext;
            if (viewModel.SelectedAlert != null)
            {
                try
                {
                    await viewModel.ResolveAlertAsync(viewModel.SelectedAlert.AlertId);
                    MessageBox.Show("Alerta marcada como resuelta", "Éxito", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    await LoadAlertsAsync();
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error al resolver alerta: {ex}", nameof(AlertViewer));
                    MessageBox.Show($"Error: {ex.Message}", "Error", 
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        
        private void OnCloseDetailsClick(object sender, RoutedEventArgs e)
        {
            DetailsPanel.Visibility = Visibility.Collapsed;
        }
    }
    
    public class AlertViewModel : INotifyPropertyChanged
    {
        private readonly LocalDatabase _localDatabase;
        private ObservableCollection<SecurityAlert> _alerts;
        private SecurityAlert _selectedAlert;
        private bool _isLoading;
        private int _totalAlerts;
        private int _criticalAlerts;
        private int _highAlerts;
        private int _mediumAlerts;
        private int _lowAlerts;
        
        public event PropertyChangedEventHandler PropertyChanged;
        
        public ObservableCollection<SecurityAlert> Alerts
        {
            get => _alerts;
            set
            {
                _alerts = value;
                OnPropertyChanged(nameof(Alerts));
            }
        }
        
        public SecurityAlert SelectedAlert
        {
            get => _selectedAlert;
            set
            {
                _selectedAlert = value;
                OnPropertyChanged(nameof(SelectedAlert));
                OnPropertyChanged(nameof(HasSelectedAlert));
            }
        }
        
        public bool HasSelectedAlert => SelectedAlert != null;
        
        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                _isLoading = value;
                OnPropertyChanged(nameof(IsLoading));
            }
        }
        
        public int TotalAlerts
        {
            get => _totalAlerts;
            set
            {
                _totalAlerts = value;
                OnPropertyChanged(nameof(TotalAlerts));
            }
        }
        
        public int CriticalAlerts
        {
            get => _criticalAlerts;
            set
            {
                _criticalAlerts = value;
                OnPropertyChanged(nameof(CriticalAlerts));
            }
        }
        
        public int HighAlerts
        {
            get => _highAlerts;
            set
            {
                _highAlerts = value;
                OnPropertyChanged(nameof(HighAlerts));
            }
        }
        
        public int MediumAlerts
        {
            get => _mediumAlerts;
            set
            {
                _mediumAlerts = value;
                OnPropertyChanged(nameof(MediumAlerts));
            }
        }
        
        public int LowAlerts
        {
            get => _lowAlerts;
            set
            {
                _lowAlerts = value;
                OnPropertyChanged(nameof(LowAlerts));
            }
        }
        
        public SeriesCollection SeveritySeries { get; set; }
        public SeriesCollection TrendSeries { get; set; }
        
        public ICommand RefreshCommand { get; }
        public ICommand ExportCommand { get; }
        public ICommand AcknowledgeCommand { get; }
        public ICommand ResolveCommand { get; }
        
        public AlertViewModel()
        {
            _localDatabase = LocalDatabase.Instance;
            Alerts = new ObservableCollection<SecurityAlert>();
            SeveritySeries = new SeriesCollection();
            TrendSeries = new SeriesCollection();
            
            RefreshCommand = new RelayCommand(async _ => await RefreshAlertsAsync());
            ExportCommand = new RelayCommand(async _ => await ExportAlertsAsync());
            AcknowledgeCommand = new RelayCommand(async param => 
            {
                if (param is string alertId)
                    await AcknowledgeAlertAsync(alertId);
            });
            ResolveCommand = new RelayCommand(async param => 
            {
                if (param is string alertId)
                    await ResolveAlertAsync(alertId);
            });
        }
        
        public void UpdateChartData(List<SecurityAlert> alerts)
        {
            // Actualizar gráfico de severidad
            SeveritySeries.Clear();
            SeveritySeries.Add(new PieSeries
            {
                Title = "Crítico",
                Values = new ChartValues<double> { alerts.Count(a => a.Severity == ThreatSeverity.Critical) },
                DataLabels = true,
                LabelPoint = point => $"{point.Y} ({point.Participation:P0})"
            });
            SeveritySeries.Add(new PieSeries
            {
                Title = "Alto",
                Values = new ChartValues<double> { alerts.Count(a => a.Severity == ThreatSeverity.High) },
                DataLabels = true
            });
            SeveritySeries.Add(new PieSeries
            {
                Title = "Medio",
                Values = new ChartValues<double> { alerts.Count(a => a.Severity == ThreatSeverity.Medium) },
                DataLabels = true
            });
            SeveritySeries.Add(new PieSeries
            {
                Title = "Bajo",
                Values = new ChartValues<double> { alerts.Count(a => a.Severity == ThreatSeverity.Low) },
                DataLabels = true
            });
            
            // Actualizar gráfico de tendencia (últimos 7 días)
            var last7Days = Enumerable.Range(0, 7)
                .Select(i => DateTime.Now.Date.AddDays(-i))
                .Reverse()
                .ToList();
                
            var dailyCounts = last7Days.Select(day => new DateValue
            {
                DateTime = day,
                Value = alerts.Count(a => a.Timestamp.Date == day)
            }).ToList();
            
            TrendSeries.Clear();
            TrendSeries.Add(new LineSeries
            {
                Title = "Alertas por día",
                Values = new ChartValues<DateValue>(dailyCounts),
                PointGeometry = DefaultGeometries.Circle,
                PointGeometrySize = 10,
                LineSmoothness = 0.5
            });
        }
        
        public async Task RefreshAlertsAsync()
        {
            IsLoading = true;
            try
            {
                var alerts = await _localDatabase.GetRecentAlertsAsync(
                    Environment.MachineName, 
                    TimeSpan.FromDays(7));
                    
                Alerts = new ObservableCollection<SecurityAlert>(alerts);
                UpdateChartData(alerts);
            }
            finally
            {
                IsLoading = false;
            }
        }
        
        public async Task ExportAlertsAsync(string filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "JSON files (*.json)|*.json|CSV files (*.csv)|*.csv",
                    DefaultExt = ".json"
                };
                
                if (dialog.ShowDialog() != true)
                    return;
                    
                filePath = dialog.FileName;
            }
            
            var exportData = Alerts.Select(a => new
            {
                a.AlertId,
                a.Timestamp,
                a.Severity,
                a.Title,
                a.Source,
                a.Status,
                a.Details
            }).ToList();
            
            var json = System.Text.Json.JsonSerializer.Serialize(exportData, 
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                
            await System.IO.File.WriteAllTextAsync(filePath, json);
        }
        
        public async Task AcknowledgeAlertAsync(string alertId)
        {
            var alert = Alerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.Status = AlertStatus.Acknowledged;
                await _localDatabase.UpdateAlertAsync(alert);
            }
        }
        
        public async Task ResolveAlertAsync(string alertId)
        {
            var alert = Alerts.FirstOrDefault(a => a.AlertId == alertId);
            if (alert != null)
            {
                alert.Status = AlertStatus.Resolved;
                await _localDatabase.UpdateAlertAsync(alert);
            }
        }
        
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
    
    public class DateValue
    {
        public DateTime DateTime { get; set; }
        public double Value { get; set; }
    }
}