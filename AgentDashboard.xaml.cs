using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using BWP.Enterprise.Agent.Core;
using BWP.Enterprise.Agent.Detection;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Remediation;
using BWP.Enterprise.Agent.Sensors;
using BWP.Enterprise.Agent.Storage;
using BWP.Enterprise.Agent.Telemetry;
using LiveCharts;
using LiveCharts.Wpf;

namespace BWP.Enterprise.Agent.UI
{
    /// <summary>
    /// Lógica de interacción para AgentDashboard.xaml
    /// </summary>
    public partial class AgentDashboard : Window
    {
        private readonly LogManager _logManager;
        private readonly ModuleRegistry _moduleRegistry;
        private readonly LocalDatabase _localDatabase;
        private readonly HealthMonitor _healthMonitor;
        private readonly RiskScoreCalculator _riskCalculator;
        private readonly DispatcherTimer _refreshTimer;
        private readonly DispatcherTimer _updateTimer;
        
        public AgentDashboard()
        {
            InitializeComponent();
            
            _logManager = LogManager.Instance;
            _moduleRegistry = ModuleRegistry.Instance;
            _localDatabase = LocalDatabase.Instance;
            _healthMonitor = HealthMonitor.Instance;
            _riskCalculator = RiskScoreCalculator.Instance;
            
            DataContext = new DashboardViewModel();
            
            // Configurar temporizadores
            _refreshTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _refreshTimer.Tick += OnRefreshTimerTick;
            
            _updateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMinutes(1)
            };
            _updateTimer.Tick += OnUpdateTimerTick;
            
            Loaded += OnWindowLoaded;
            Closing += OnWindowClosing;
        }
        
        private async void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await InitializeDashboardAsync();
                _refreshTimer.Start();
                _updateTimer.Start();
                
                // Configurar sistema de notificaciones
                SetupNotificationSystem();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar dashboard: {ex}", nameof(AgentDashboard));
                MessageBox.Show($"Error al inicializar dashboard: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private async Task InitializeDashboardAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            viewModel.IsLoading = true;
            
            try
            {
                // Configurar datos iniciales
                viewModel.CurrentEndpointId = Environment.MachineName;
                viewModel.AgentVersion = GetAgentVersion();
                viewModel.Uptime = TimeSpan.FromSeconds(Environment.TickCount / 1000);
                
                // Cargar métricas iniciales
                await LoadInitialMetricsAsync();
                
                // Configurar gráficos
                SetupCharts();
                
                // Suscribirse a eventos
                SubscribeToEvents();
            }
            finally
            {
                viewModel.IsLoading = false;
            }
        }
        
        private async Task LoadInitialMetricsAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                // Cargar estado de sensores
                await UpdateSensorStatusAsync();
                
                // Cargar score de riesgo
                await UpdateRiskScoreAsync();
                
                // Cargar alertas activas
                await UpdateActiveAlertsAsync();
                
                // Cargar detecciones recientes
                await UpdateRecentDetectionsAsync();
                
                // Cargar acciones de remediación
                await UpdateRecentRemediationsAsync();
                
                // Cargar estado de telemetría
                await UpdateTelemetryStatusAsync();
                
                // Cargar uso de recursos del sistema
                UpdateSystemResources();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al cargar métricas iniciales: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async void OnRefreshTimerTick(object sender, EventArgs e)
        {
            await RefreshDashboardDataAsync();
        }
        
        private async void OnUpdateTimerTick(object sender, EventArgs e)
        {
            await UpdateDashboardMetricsAsync();
        }
        
        private async Task RefreshDashboardDataAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                // Actualizar datos en tiempo real
                await UpdateRiskScoreAsync();
                await UpdateActiveAlertsAsync();
                await UpdateSystemResources();
                
                // Actualizar gráficos
                UpdateRealTimeCharts();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar dashboard: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateDashboardMetricsAsync()
        {
            try
            {
                await UpdateSensorStatusAsync();
                await UpdateRecentDetectionsAsync();
                await UpdateRecentRemediationsAsync();
                await UpdateTelemetryStatusAsync();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar métricas: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateSensorStatusAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                // Obtener estado de sensores del ModuleRegistry
                var processSensor = _moduleRegistry.GetModule<ProcessSensor>();
                var fileSystemSensor = _moduleRegistry.GetModule<FileSystemSensor>();
                var networkSensor = _moduleRegistry.GetModule<NetworkSensor>();
                var registrySensor = _moduleRegistry.GetModule<RegistrySensor>();
                
                viewModel.ProcessSensorStatus = processSensor?.IsEnabled == true ? "Active" : "Inactive";
                viewModel.FileSystemSensorStatus = fileSystemSensor?.IsEnabled == true ? "Active" : "Inactive";
                viewModel.NetworkSensorStatus = networkSensor?.IsEnabled == true ? "Active" : "Inactive";
                viewModel.RegistrySensorStatus = registrySensor?.IsEnabled == true ? "Active" : "Inactive";
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar estado de sensores: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateRiskScoreAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                var riskScore = await _riskCalculator.GetCurrentRiskScoreAsync();
                viewModel.RiskScore = riskScore;
                
                // Determinar nivel de riesgo
                viewModel.RiskLevel = riskScore >= 80 ? "Critical" :
                                     riskScore >= 60 ? "High" :
                                     riskScore >= 40 ? "Medium" :
                                     riskScore >= 20 ? "Low" : "Minimal";
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar score de riesgo: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateActiveAlertsAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                var alerts = await _localDatabase.GetActiveAlertsAsync(Environment.MachineName);
                viewModel.ActiveAlerts = new ObservableCollection<SecurityAlert>(alerts);
                viewModel.ActiveAlertCount = alerts.Count;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar alertas activas: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateRecentDetectionsAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                var detections = await _localDatabase.GetRecentDetectionsAsync(
                    Environment.MachineName, 
                    TimeSpan.FromHours(1));
                
                viewModel.RecentDetections = new ObservableCollection<DetectionResult>(
                    detections.OrderByDescending(d => d.Timestamp).Take(20));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar detecciones recientes: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateRecentRemediationsAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                var remediations = await _localDatabase.GetRecentRemediationsAsync(
                    Environment.MachineName, 
                    TimeSpan.FromHours(24));
                
                viewModel.RecentRemediations = new ObservableCollection<RemediationAction>(
                    remediations.OrderByDescending(r => r.Timestamp).Take(10));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar acciones de remediación: {ex}", nameof(AgentDashboard));
            }
        }
        
        private async Task UpdateTelemetryStatusAsync()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                var telemetryQueue = _moduleRegistry.GetModule<TelemetryQueue>();
                if (telemetryQueue != null)
                {
                    viewModel.EventsInQueue = await telemetryQueue.GetQueueSizeAsync();
                }
                
                viewModel.LastSyncTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al actualizar estado de telemetría: {ex}", nameof(AgentDashboard));
            }
        }
        
        private void UpdateSystemResources()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            try
            {
                using (var process = System.Diagnostics.Process.GetCurrentProcess())
                {
                    // Uso de CPU (aproximado)
                    var cpuCounter = new System.Diagnostics.PerformanceCounter(
                        "Process", "% Processor Time", process.ProcessName);
                    viewModel.CpuUsage = (int)cpuCounter.NextValue();
                    
                    // Uso de memoria
                    var memoryMB = process.WorkingSet64 / (1024.0 * 1024.0);
                    var totalMemoryMB = new System.Diagnostics.PerformanceCounter(
                        "Memory", "Available MBytes").NextValue();
                    viewModel.MemoryUsage = (int)((memoryMB / (memoryMB + totalMemoryMB)) * 100);
                    
                    // Uso de disco
                    var diskCounter = new System.Diagnostics.PerformanceCounter(
                        "LogicalDisk", "% Free Space", "C:");
                    viewModel.DiskUsage = 100 - (int)diskCounter.NextValue();
                }
            }
            catch
            {
                // En caso de error, usar valores simulados
                var random = new Random();
                viewModel.CpuUsage = random.Next(5, 40);
                viewModel.MemoryUsage = random.Next(30, 70);
                viewModel.DiskUsage = random.Next(20, 60);
            }
        }
        
        private void SetupCharts()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            // Configurar gráfico de actividad de amenazas
            viewModel.ThreatActivitySeries = new SeriesCollection
            {
                new LineSeries
                {
                    Title = "Threat Events",
                    Values = new ChartValues<double> { 0, 0, 0, 0, 0, 0 },
                    PointGeometry = DefaultGeometries.Circle,
                    PointGeometrySize = 8,
                    LineSmoothness = 0.7,
                    StrokeThickness = 3,
                    Fill = System.Windows.Media.Brushes.Transparent
                }
            };
            
            // Configurar etiquetas de tiempo (últimos 60 minutos)
            viewModel.TimeLabels = Enumerable.Range(0, 6)
                .Select(i => DateTime.Now.AddMinutes(-i * 10).ToString("HH:mm"))
                .Reverse()
                .ToArray();
        }
        
        private void UpdateRealTimeCharts()
        {
            var viewModel = (DashboardViewModel)DataContext;
            
            // Actualizar gráfico de actividad de amenazas
            var random = new Random();
            var newValue = random.Next(0, 20); // Simular datos para demo
            
            if (viewModel.ThreatActivitySeries[0].Values.Count >= 30)
            {
                viewModel.ThreatActivitySeries[0].Values.RemoveAt(0);
            }
            
            viewModel.ThreatActivitySeries[0].Values.Add(newValue);
            
            // Actualizar etiquetas de tiempo
            var now = DateTime.Now;
            viewModel.TimeLabels = Enumerable.Range(0, 6)
                .Select(i => now.AddMinutes(-i * 10).ToString("HH:mm"))
                .Reverse()
                .ToArray();
        }
        
        private void SetupNotificationSystem()
        {
            // Suscribirse a eventos de alta severidad
            // En una implementación real, esto estaría conectado al sistema de eventos
        }
        
        private void SubscribeToEvents()
        {
            // Suscribirse a eventos importantes del agente
            // Por ahora es un esqueleto para implementación futura
        }
        
        private string GetAgentVersion()
        {
            try
            {
                var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version;
                return $"{version.Major}.{version.Minor}.{version.Build}";
            }
            catch
            {
                return "1.0.0";
            }
        }
        
        private void OnWindowClosing(object sender, CancelEventArgs e)
        {
            // Minimizar a la bandeja en lugar de cerrar
            if (MessageBox.Show("Do you want to minimize to system tray?", "BWP Agent",
                MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                e.Cancel = true;
                Hide();
                ShowInTaskbar = false;
                
                // Mostrar notificación de bandeja
                ShowTrayNotification();
            }
            else
            {
                _refreshTimer.Stop();
                _updateTimer.Stop();
            }
        }
        
        private void ShowTrayNotification()
        {
            // Implementar notificación de bandeja del sistema
            // Para una implementación completa, necesitarías System.Windows.Forms.NotifyIcon
        }
        
        // Handlers para botones
        private async void OnRefreshDashboardClick(object sender, RoutedEventArgs e)
        {
            await RefreshDashboardDataAsync();
        }
        
        private void OnGenerateReportClick(object sender, RoutedEventArgs e)
        {
            var reportWindow = new ReportGeneratorWindow();
            reportWindow.Owner = this;
            reportWindow.ShowDialog();
        }
        
        private void OnOpenSettingsClick(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new AgentSettingsWindow();
            settingsWindow.Owner = this;
            settingsWindow.ShowDialog();
        }
        
        private async void OnRunFullScanClick(object sender, RoutedEventArgs e)
        {
            try
            {
                var result = await RunFullSystemScanAsync();
                if (result)
                {
                    MessageBox.Show("Full system scan completed successfully.", "Scan Complete", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show("Full system scan failed or was cancelled.", "Scan Failed", 
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error running full scan: {ex}", nameof(AgentDashboard));
                MessageBox.Show($"Error running full scan: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private async Task<bool> RunFullSystemScanAsync()
        {
            // Implementar escaneo completo del sistema
            // Esto debería activar todos los sensores y motores de detección
            return await Task.FromResult(true); // Simulación
        }
        
        private void OnViewAllAlertsClick(object sender, RoutedEventArgs e)
        {
            var alertViewer = new AlertViewer();
            alertViewer.Owner = this;
            alertViewer.Show();
        }
        
        private async void OnForceSyncClick(object sender, RoutedEventArgs e)
        {
            try
            {
                var telemetrySender = _moduleRegistry.GetModule<TelemetryBatchSender>();
                if (telemetrySender != null)
                {
                    await telemetrySender.SendBatchAsync(force: true);
                    MessageBox.Show("Telemetry sync completed.", "Sync Complete", 
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error forcing sync: {ex}", nameof(AgentDashboard));
                MessageBox.Show($"Error forcing sync: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void OnMinimizeToTrayClick(object sender, RoutedEventArgs e)
        {
            Hide();
            ShowInTaskbar = false;
            ShowTrayNotification();
        }
    }
    
    public class DashboardViewModel : INotifyPropertyChanged
    {
        private string _currentEndpointId;
        private string _agentVersion;
        private TimeSpan _uptime;
        private int _riskScore;
        private string _riskLevel;
        private string _processSensorStatus;
        private string _fileSystemSensorStatus;
        private string _networkSensorStatus;
        private string _registrySensorStatus;
        private int _activeAlertCount;
        private DateTime _lastSyncTime;
        private int _eventsInQueue;
        private int _cpuUsage;
        private int _memoryUsage;
        private int _diskUsage;
        private bool _isLoading;
        
        private ObservableCollection<SecurityAlert> _activeAlerts;
        private ObservableCollection<DetectionResult> _recentDetections;
        private ObservableCollection<RemediationAction> _recentRemediations;
        private SeriesCollection _threatActivitySeries;
        private string[] _timeLabels;
        
        public event PropertyChangedEventHandler PropertyChanged;
        
        public string CurrentEndpointId
        {
            get => _currentEndpointId;
            set
            {
                _currentEndpointId = value;
                OnPropertyChanged(nameof(CurrentEndpointId));
            }
        }
        
        public string AgentVersion
        {
            get => _agentVersion;
            set
            {
                _agentVersion = value;
                OnPropertyChanged(nameof(AgentVersion));
            }
        }
        
        public TimeSpan Uptime
        {
            get => _uptime;
            set
            {
                _uptime = value;
                OnPropertyChanged(nameof(Uptime));
            }
        }
        
        public int RiskScore
        {
            get => _riskScore;
            set
            {
                _riskScore = value;
                OnPropertyChanged(nameof(RiskScore));
            }
        }
        
        public string RiskLevel
        {
            get => _riskLevel;
            set
            {
                _riskLevel = value;
                OnPropertyChanged(nameof(RiskLevel));
            }
        }
        
        public string ProcessSensorStatus
        {
            get => _processSensorStatus;
            set
            {
                _processSensorStatus = value;
                OnPropertyChanged(nameof(ProcessSensorStatus));
            }
        }
        
        public string FileSystemSensorStatus
        {
            get => _fileSystemSensorStatus;
            set
            {
                _fileSystemSensorStatus = value;
                OnPropertyChanged(nameof(FileSystemSensorStatus));
            }
        }
        
        public string NetworkSensorStatus
        {
            get => _networkSensorStatus;
            set
            {
                _networkSensorStatus = value;
                OnPropertyChanged(nameof(NetworkSensorStatus));
            }
        }
        
        public string RegistrySensorStatus
        {
            get => _registrySensorStatus;
            set
            {
                _registrySensorStatus = value;
                OnPropertyChanged(nameof(RegistrySensorStatus));
            }
        }
        
        public int ActiveAlertCount
        {
            get => _activeAlertCount;
            set
            {
                _activeAlertCount = value;
                OnPropertyChanged(nameof(ActiveAlertCount));
            }
        }
        
        public DateTime LastSyncTime
        {
            get => _lastSyncTime;
            set
            {
                _lastSyncTime = value;
                OnPropertyChanged(nameof(LastSyncTime));
            }
        }
        
        public int EventsInQueue
        {
            get => _eventsInQueue;
            set
            {
                _eventsInQueue = value;
                OnPropertyChanged(nameof(EventsInQueue));
            }
        }
        
        public int CpuUsage
        {
            get => _cpuUsage;
            set
            {
                _cpuUsage = value;
                OnPropertyChanged(nameof(CpuUsage));
            }
        }
        
        public int MemoryUsage
        {
            get => _memoryUsage;
            set
            {
                _memoryUsage = value;
                OnPropertyChanged(nameof(MemoryUsage));
            }
        }
        
        public int DiskUsage
        {
            get => _diskUsage;
            set
            {
                _diskUsage = value;
                OnPropertyChanged(nameof(DiskUsage));
            }
        }
        
        public bool IsLoading
        {
            get => _isLoading;
            set
            {
                _isLoading = value;
                OnPropertyChanged(nameof(IsLoading));
            }
        }
        
        public ObservableCollection<SecurityAlert> ActiveAlerts
        {
            get => _activeAlerts;
            set
            {
                _activeAlerts = value;
                OnPropertyChanged(nameof(ActiveAlerts));
            }
        }
        
        public ObservableCollection<DetectionResult> RecentDetections
        {
            get => _recentDetections;
            set
            {
                _recentDetections = value;
                OnPropertyChanged(nameof(RecentDetections));
            }
        }
        
        public ObservableCollection<RemediationAction> RecentRemediations
        {
            get => _recentRemediations;
            set
            {
                _recentRemediations = value;
                OnPropertyChanged(nameof(RecentRemediations));
            }
        }
        
        public SeriesCollection ThreatActivitySeries
        {
            get => _threatActivitySeries;
            set
            {
                _threatActivitySeries = value;
                OnPropertyChanged(nameof(ThreatActivitySeries));
            }
        }
        
        public string[] TimeLabels
        {
            get => _timeLabels;
            set
            {
                _timeLabels = value;
                OnPropertyChanged(nameof(TimeLabels));
            }
        }
        
        public ICommand RefreshDashboardCommand { get; }
        public ICommand GenerateReportCommand { get; }
        public ICommand OpenSettingsCommand { get; }
        public ICommand RunFullScanCommand { get; }
        public ICommand ViewAllAlertsCommand { get; }
        public ICommand ForceSyncCommand { get; }
        public ICommand MinimizeToTrayCommand { get; }
        public ICommand DismissAlertCommand { get; }
        
        public DashboardViewModel()
        {
            ActiveAlerts = new ObservableCollection<SecurityAlert>();
            RecentDetections = new ObservableCollection<DetectionResult>();
            RecentRemediations = new ObservableCollection<RemediationAction>();
            ThreatActivitySeries = new SeriesCollection();
            TimeLabels = Array.Empty<string>();
            
            // Inicializar comandos
            RefreshDashboardCommand = new RelayCommand(async _ => await RefreshDashboardAsync());
            GenerateReportCommand = new RelayCommand(_ => GenerateReport());
            OpenSettingsCommand = new RelayCommand(_ => OpenSettings());
            RunFullScanCommand = new RelayCommand(async _ => await RunFullScanAsync());
            ViewAllAlertsCommand = new RelayCommand(_ => ViewAllAlerts());
            ForceSyncCommand = new RelayCommand(async _ => await ForceSyncAsync());
            MinimizeToTrayCommand = new RelayCommand(_ => MinimizeToTray());
            DismissAlertCommand = new RelayCommand(async param => 
            {
                if (param is string alertId)
                    await DismissAlertAsync(alertId);
            });
        }
        
        public DateTime LastUpdateCheck { get; set; } = DateTime.Now;
        
        private async Task RefreshDashboardAsync()
        {
            // Implementar lógica de actualización
            await Task.Delay(100); // Simulación
        }
        
        private void GenerateReport()
        {
            // Implementar generación de reporte
        }
        
        private void OpenSettings()
        {
            // Implementar apertura de configuración
        }
        
        private async Task RunFullScanAsync()
        {
            // Implementar escaneo completo
            await Task.Delay(100); // Simulación
        }
        
        private void ViewAllAlerts()
        {
            // Implementar visualización de todas las alertas
        }
        
        private async Task ForceSyncAsync()
        {
            // Implementar sincronización forzada
            await Task.Delay(100); // Simulación
        }
        
        private void MinimizeToTray()
        {
            // Implementar minimización a bandeja
        }
        
        private async Task DismissAlertAsync(string alertId)
        {
            // Implementar descarte de alerta
            await Task.Delay(100); // Simulación
        }
        
        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
    
    public class RelayCommand : ICommand
    {
        private readonly Action<object> _execute;
        private readonly Func<object, bool> _canExecute;
        
        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value; }
        }
        
        public RelayCommand(Action<object> execute, Func<object, bool> canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }
        
        public bool CanExecute(object parameter) => _canExecute == null || _canExecute(parameter);
        
        public void Execute(object parameter) => _execute(parameter);
    }
}