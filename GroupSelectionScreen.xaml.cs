using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using BWP.Enterprise.Cloud.TenantManagement;
using BWP.Enterprise.Installer.Engine;

namespace BWP.Enterprise.Installer.UI
{
    public partial class GroupSelectionScreen : Window, INotifyPropertyChanged
    {
        private readonly string _tenantToken;
        private readonly string _deviceName;
        private CancellationTokenSource _suggestionCts;

        // Propiedades bindeables
        private string _selectedGroup;
        private ObservableCollection<GroupSuggestion> _suggestions;
        private GroupSuggestion _selectedSuggestion;
        private bool _isCreatingNewGroup;
        private string _newGroupDescription;
        private string _recommendedGroupMessage;
        private bool _hasRecommendation;
        private string _validationMessage;
        private Brush _validationStatusColor;
        private bool _isGroupValid;

        public event PropertyChangedEventHandler PropertyChanged;

        // Binding Properties
        public string SelectedGroup 
        { 
            get => _selectedGroup; 
            set { _selectedGroup = value; OnPropertyChanged(); ValidateGroup(); } 
        }
        
        public ObservableCollection<GroupSuggestion> Suggestions 
        { 
            get => _suggestions; 
            set { _suggestions = value; OnPropertyChanged(); HasSuggestions = value?.Any() == true; } 
        }
        
        public bool HasSuggestions => Suggestions?.Any() == true;
        public GroupSuggestion SelectedSuggestion 
        { 
            get => _selectedSuggestion; 
            set { _selectedSuggestion = value; OnPropertyChanged(); } 
        }
        
        public bool IsCreatingNewGroup 
        { 
            get => _isCreatingNewGroup; 
            set { _isCreatingNewGroup = value; OnPropertyChanged(); ValidateGroup(); } 
        }
        
        public string NewGroupDescription 
        { 
            get => _newGroupDescription; 
            set { _newGroupDescription = value; OnPropertyChanged(); ValidateGroup(); } 
        }
        
        public string RecommendedGroupMessage 
        { 
            get => _recommendedGroupMessage; 
            set { _recommendedGroupMessage = value; OnPropertyChanged(); } 
        }
        
        public bool HasRecommendation 
        { 
            get => _hasRecommendation; 
            set { _hasRecommendation = value; OnPropertyChanged(); } 
        }
        
        public string ValidationMessage 
        { 
            get => _validationMessage; 
            set { _validationMessage = value; OnPropertyChanged(); } 
        }
        
        public Brush ValidationStatusColor 
        { 
            get => _validationStatusColor; 
            set { _validationStatusColor = value; OnPropertyChanged(); } 
        }
        
        public bool IsGroupValid 
        { 
            get => _isGroupValid; 
            set { _isGroupValid = value; OnPropertyChanged(); } 
        }

        public GroupSelectionScreen(string tenantToken)
        {
            InitializeComponent();
            DataContext = this;

            _tenantToken = tenantToken;
            _deviceName = Environment.MachineName;
            _suggestions = new ObservableCollection<GroupSuggestion>();
            _suggestionCts = new CancellationTokenSource();

            this.Loaded += async (s, e) => 
            {
                await LoadInitialSuggestionsAsync();
                GenerateSmartRecommendation();
            };
        }

        private async Task LoadInitialSuggestionsAsync()
        {
            try
            {
                // Cargar grupos existentes desde el cloud
                var httpClient = InstallerHttpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Add("X-Tenant-Token", _tenantToken);

                var response = await httpClient.GetAsync("https://api.bwp.enterprise/v1/tenant/groups");
                
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var groups = JsonSerializer.Deserialize<List<TenantGroup>>(json, 
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                    // Cachear localmente para autocompletado rápido
                    GroupCache.Instance.UpdateGroups(groups);
                }
            }
            catch (Exception ex)
            {
                // Si no hay conexión, usar cache local de la última sesión
                var cachedGroups = GroupCache.Instance.GetGroups();
                if (cachedGroups.Any())
                {
                    // Continuar con cache
                }
                else
                {
                    ValidationMessage = "No se pudo conectar con el cloud. Verifica tu conexión a internet.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Amarillo
                }
            }
        }

        private void GenerateSmartRecommendation()
        {
            // Algoritmo de recomendación basado en el nombre del equipo
            string recommendation = null;
            
            if (_deviceName.StartsWith("SRV", StringComparison.OrdinalIgnoreCase) ||
                _deviceName.Contains("SERVER", StringComparison.OrdinalIgnoreCase))
            {
                recommendation = "Servers";
                RecommendedGroupMessage = "Basado en el nombre del equipo, recomendamos el grupo 'Servers' (políticas de alta seguridad para servidores).";
            }
            else if (_deviceName.StartsWith("WS", StringComparison.OrdinalIgnoreCase) ||
                     _deviceName.StartsWith("PC", StringComparison.OrdinalIgnoreCase) ||
                     _deviceName.StartsWith("DESKTOP", StringComparison.OrdinalIgnoreCase))
            {
                recommendation = "Workstations";
                RecommendedGroupMessage = "Basado en el nombre del equipo, recomendamos el grupo 'Workstations' (políticas estándar para estaciones de trabajo).";
            }
            else if (_deviceName.StartsWith("DC", StringComparison.OrdinalIgnoreCase))
            {
                recommendation = "DomainControllers";
                RecommendedGroupMessage = "Basado en el nombre del equipo, recomendamos el grupo 'DomainControllers' (políticas críticas para DC).";
            }

            if (!string.IsNullOrEmpty(recommendation))
            {
                // Verificar si el grupo recomendado existe en el tenant
                var existingGroup = GroupCache.Instance.FindGroup(recommendation);
                if (existingGroup != null)
                {
                    SelectedGroup = existingGroup.Name;
                    HasRecommendation = true;
                }
            }
        }

        private async void GroupTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            // Cancelar búsqueda anterior
            _suggestionCts?.Cancel();
            _suggestionCts = new CancellationTokenSource();
            
            var text = GroupTextBox.Text;
            
            if (string.IsNullOrWhiteSpace(text) || text.Length < 2)
            {
                Suggestions?.Clear();
                return;
            }

            try
            {
                await Task.Delay(300, _suggestionCts.Token); // Debounce
                
                var results = await Task.Run(() => 
                {
                    // Fuzzy matching sobre grupos cacheados
                    return GroupCache.Instance.SearchGroups(text, 5)
                        .Select(g => new GroupSuggestion 
                        { 
                            Name = g.Name, 
                            DisplayName = g.Name,
                            Description = g.Description,
                            DeviceCount = g.DeviceCount,
                            IsSystemGroup = g.IsSystem
                        }).ToList();
                }, _suggestionCts.Token);

                Application.Current.Dispatcher.Invoke(() =>
                {
                    Suggestions.Clear();
                    foreach (var r in results)
                        Suggestions.Add(r);
                });
            }
            catch (TaskCanceledException) { }
        }

        private void ValidateGroup()
        {
            if (IsCreatingNewGroup)
            {
                // Validación para nuevo grupo
                if (string.IsNullOrWhiteSpace(SelectedGroup))
                {
                    ValidationMessage = "El nombre del grupo no puede estar vacío.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Rojo
                    IsGroupValid = false;
                }
                else if (GroupCache.Instance.GroupExists(SelectedGroup))
                {
                    ValidationMessage = "El grupo ya existe. Desmarca 'Crear nuevo grupo' para seleccionarlo.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Amarillo
                    IsGroupValid = false;
                }
                else if (string.IsNullOrWhiteSpace(NewGroupDescription))
                {
                    ValidationMessage = "Proporciona una descripción para el nuevo grupo.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Amarillo
                    IsGroupValid = false;
                }
                else
                {
                    ValidationMessage = "Nuevo grupo válido. Será creado durante la instalación.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(40, 167, 69)); // Verde
                    IsGroupValid = true;
                }
            }
            else
            {
                // Validación para grupo existente
                if (string.IsNullOrWhiteSpace(SelectedGroup))
                {
                    ValidationMessage = "Selecciona o escribe un grupo existente.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Amarillo
                    IsGroupValid = false;
                }
                else if (GroupCache.Instance.GroupExists(SelectedGroup))
                {
                    ValidationMessage = $"Grupo válido: {SelectedGroup}";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(40, 167, 69)); // Verde
                    IsGroupValid = true;
                }
                else
                {
                    ValidationMessage = "El grupo no existe en el tenant. Marca 'Crear nuevo grupo' si deseas crearlo.";
                    ValidationStatusColor = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Amarillo
                    IsGroupValid = false;
                }
            }
        }

        private void ApplyRecommendation_Click(object sender, RoutedEventArgs e)
        {
            if (HasRecommendation)
            {
                GroupTextBox.Text = RecommendedGroupMessage?.Split('\'')[1]; // Hack simple
            }
        }

        private void SuggestionsListBox_PreviewMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (SuggestionsListBox.SelectedItem is GroupSuggestion selected)
            {
                SelectedGroup = selected.Name;
                IsCreatingNewGroup = false;
                Suggestions.Clear();
            }
        }

        private void GroupTextBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Down && Suggestions.Any())
            {
                SuggestionsListBox.Focus();
                SuggestionsListBox.SelectedIndex = 0;
                e.Handled = true;
            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            var welcomeScreen = new WelcomeScreen();
            welcomeScreen.Show();
            this.Close();
        }

        private void NextButton_Click(object sender, RoutedEventArgs e)
        {
            var permissionsScreen = new PermissionsScreen(_tenantToken, SelectedGroup, IsCreatingNewGroup, NewGroupDescription);
            permissionsScreen.Show();
            this.Close();
        }

        protected void OnPropertyChanged([System.Runtime.CompilerServices.CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    // Modelos auxiliares
    public class GroupSuggestion
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public int DeviceCount { get; set; }
        public bool IsSystemGroup { get; set; }
    }

    public class TenantGroup
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public int DeviceCount { get; set; }
        public bool IsSystem { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    // Cache Singleton para grupos (evita round-trips innecesarios)
    public sealed class GroupCache
    {
        private static readonly Lazy<GroupCache> _instance = new Lazy<GroupCache>(() => new GroupCache());
        public static GroupCache Instance => _instance.Value;

        private List<TenantGroup> _cachedGroups = new List<TenantGroup>();
        private readonly object _lock = new object();

        public void UpdateGroups(List<TenantGroup> groups)
        {
            lock (_lock)
            {
                _cachedGroups = groups;
            }
        }

        public List<TenantGroup> GetGroups()
        {
            lock (_lock) { return _cachedGroups.ToList(); }
        }

        public bool GroupExists(string groupName)
        {
            lock (_lock)
            {
                return _cachedGroups.Any(g => 
                    g.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
            }
        }

        public TenantGroup FindGroup(string groupName)
        {
            lock (_lock)
            {
                return _cachedGroups.FirstOrDefault(g => 
                    g.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
            }
        }

        public List<TenantGroup> SearchGroups(string query, int maxResults)
        {
            lock (_lock)
            {
                // Fuzzy matching simple (en producción usar algo más robusto)
                return _cachedGroups
                    .Where(g => g.Name.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                    .OrderBy(g => g.Name)
                    .Take(maxResults)
                    .ToList();
            }
        }
    }
}