using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Diagnostics;
using System.IO;

namespace BWP.Installer.UI
{
    public partial class WelcomeScreen : Window
    {
        private InstallerNavigationService _navigationService;
        private InstallationConfiguration _config;
        
        public WelcomeScreen(InstallerNavigationService navigationService, InstallationConfiguration config)
        {
            InitializeComponent();
            
            _navigationService = navigationService;
            _config = config;
            
            // Configurar eventos
            Loaded += OnWindowLoaded;
            MouseLeftButtonDown += OnWindowMouseLeftButtonDown;
            
            // Establecer efectos de sombra
            SetWindowEffects();
            
            // Actualizar información de versión
            UpdateVersionInfo();
        }
        
        private void OnWindowLoaded(object sender, RoutedEventArgs e)
        {
            // Animar entrada
            AnimateEntrance();
            
            // Verificar requisitos del sistema
            CheckSystemRequirements();
            
            // Configurar tooltips
            SetupTooltips();
        }
        
        private void OnWindowMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }
        
        private void SetWindowEffects()
        {
            // Crear efecto de sombra
            DropShadowEffect dropShadow = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = Colors.Black,
                Direction = 320,
                ShadowDepth = 10,
                Opacity = 0.3,
                BlurRadius = 20,
                RenderingBias = System.Windows.Media.Effects.RenderingBias.Performance
            };
            
            // Buscar el borde principal
            if (Template != null)
            {
                Border mainBorder = Template.FindName("MainBorder", this) as Border;
                if (mainBorder != null)
                {
                    mainBorder.Effect = dropShadow;
                }
            }
        }
        
        private void AnimateEntrance()
        {
            // Animación de opacidad
            DoubleAnimation opacityAnimation = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromSeconds(0.5),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            
            BeginAnimation(OpacityProperty, opacityAnimation);
            
            // Animación de escala
            ScaleTransform scaleTransform = new ScaleTransform(0.95, 0.95);
            RenderTransform = scaleTransform;
            RenderTransformOrigin = new Point(0.5, 0.5);
            
            DoubleAnimation scaleXAnimation = new DoubleAnimation
            {
                From = 0.95,
                To = 1,
                Duration = TimeSpan.FromSeconds(0.6),
                EasingFunction = new ElasticEase 
                { 
                    Oscillations = 1,
                    Springiness = 4,
                    EasingMode = EasingMode.EaseOut
                }
            };
            
            DoubleAnimation scaleYAnimation = new DoubleAnimation
            {
                From = 0.95,
                To = 1,
                Duration = TimeSpan.FromSeconds(0.6),
                EasingFunction = new ElasticEase 
                { 
                    Oscillations = 1,
                    Springiness = 4,
                    EasingMode = EasingMode.EaseOut
                }
            };
            
            scaleTransform.BeginAnimation(ScaleTransform.ScaleXProperty, scaleXAnimation);
            scaleTransform.BeginAnimation(ScaleTransform.ScaleYProperty, scaleYAnimation);
        }
        
        private void UpdateVersionInfo()
        {
            try
            {
                // Obtener versión del ensamblado
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                if (version != null)
                {
                    // Buscar TextBlock de versión
                    var versionTextBlock = Template?.FindName("VersionTextBlock", this) as TextBlock;
                    if (versionTextBlock != null)
                    {
                        versionTextBlock.Text = $"v{version.Major}.{version.Minor}.{version.Build}";
                    }
                }
            }
            catch
            {
                // Usar versión por defecto
            }
        }
        
        private void CheckSystemRequirements()
        {
            bool requirementsMet = true;
            var requirements = new SystemRequirements();
            
            // Verificar sistema operativo
            if (!requirements.IsWindowsVersionSupported())
            {
                requirementsMet = false;
                ShowRequirementWarning("Sistema operativo no soportado. Se requiere Windows 10/11 o Windows Server 2016+.");
            }
            
            // Verificar arquitectura
            if (!requirements.Is64BitArchitecture())
            {
                requirementsMet = false;
                ShowRequirementWarning("Arquitectura no soportada. Se requiere sistema operativo de 64 bits.");
            }
            
            // Verificar privilegios de administrador
            if (!requirements.IsRunningAsAdministrator())
            {
                requirementsMet = false;
                ShowRequirementWarning("Se requieren privilegios de administrador para la instalación.");
            }
            
            // Verificar espacio en disco
            long requiredSpace = 500 * 1024 * 1024; // 500MB
            if (!requirements.HasSufficientDiskSpace(requiredSpace))
            {
                requirementsMet = false;
                ShowRequirementWarning($"Espacio insuficiente en disco. Se requieren {requiredSpace / (1024 * 1024)} MB libres.");
            }
            
            // Verificar .NET Framework
            if (!requirements.IsDotNetFrameworkInstalled())
            {
                requirementsMet = false;
                ShowRequirementWarning(".NET Framework 4.8 o superior es requerido.");
            }
            
            // Habilitar/deshabilitar botón siguiente según requisitos
            NextButton.IsEnabled = requirementsMet && (AcceptTermsCheckBox?.IsChecked == true);
            
            // Mostrar advertencias si hay requisitos no cumplidos
            if (!requirementsMet)
            {
                ShowRequirementsWarningPanel();
            }
        }
        
        private void ShowRequirementWarning(string message)
        {
            // Este método sería implementado para mostrar advertencias específicas
            // En una implementación completa, se mostraría un panel con las advertencias
        }
        
        private void ShowRequirementsWarningPanel()
        {
            // Implementar panel de advertencias de requisitos
            // Podría ser un UserControl que se muestra sobre la ventana principal
        }
        
        private void SetupTooltips()
        {
            // Configurar tooltips para botones
            CancelButton.ToolTip = "Cancelar la instalación";
            NextButton.ToolTip = "Continuar con la instalación";
            CloseButton.ToolTip = "Cerrar el instalador";
            TermsLink.ToolTip = "Ver términos y condiciones de uso";
            
            // Tooltip para características
            SetupFeatureTooltips();
        }
        
        private void SetupFeatureTooltips()
        {
            // En una implementación completa, se agregarían tooltips detallados
            // para cada característica mencionada
        }
        
        private void AcceptTermsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            UpdateNextButtonState();
            
            // Animación de check
            AnimateCheckBox(true);
        }
        
        private void AcceptTermsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            UpdateNextButtonState();
            
            // Animación de uncheck
            AnimateCheckBox(false);
        }
        
        private void UpdateNextButtonState()
        {
            bool requirementsMet = true; // En realidad se verificarían los requisitos
            bool termsAccepted = AcceptTermsCheckBox.IsChecked == true;
            
            NextButton.IsEnabled = requirementsMet && termsAccepted;
            
            // Animación de cambio de estado
            if (NextButton.IsEnabled)
            {
                AnimateButtonEnable();
            }
            else
            {
                AnimateButtonDisable();
            }
        }
        
        private void AnimateCheckBox(bool isChecked)
        {
            if (AcceptTermsCheckBox.Template.FindName("CheckMark", AcceptTermsCheckBox) is Path checkMark)
            {
                DoubleAnimation animation = new DoubleAnimation
                {
                    From = isChecked ? 0 : 1,
                    To = isChecked ? 1 : 0,
                    Duration = TimeSpan.FromSeconds(0.2),
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                };
                
                checkMark.BeginAnimation(OpacityProperty, animation);
            }
        }
        
        private void AnimateButtonEnable()
        {
            ColorAnimation backgroundColorAnimation = new ColorAnimation
            {
                To = Color.FromRgb(0, 120, 212), // #0078D4
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            
            ColorAnimation foregroundColorAnimation = new ColorAnimation
            {
                To = Colors.White,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            
            if (NextButton.Background is SolidColorBrush backgroundBrush)
            {
                backgroundBrush.BeginAnimation(SolidColorBrush.ColorProperty, backgroundColorAnimation);
            }
            
            if (NextButton.Foreground is SolidColorBrush foregroundBrush)
            {
                foregroundBrush.BeginAnimation(SolidColorBrush.ColorProperty, foregroundColorAnimation);
            }
        }
        
        private void AnimateButtonDisable()
        {
            ColorAnimation backgroundColorAnimation = new ColorAnimation
            {
                To = Color.FromRgb(204, 204, 204), // #CCCCCC
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            
            ColorAnimation foregroundColorAnimation = new ColorAnimation
            {
                To = Color.FromRgb(136, 136, 136), // #888888
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            
            if (NextButton.Background is SolidColorBrush backgroundBrush)
            {
                backgroundBrush.BeginAnimation(SolidColorBrush.ColorProperty, backgroundColorAnimation);
            }
            
            if (NextButton.Foreground is SolidColorBrush foregroundBrush)
            {
                foregroundBrush.BeginAnimation(SolidColorBrush.ColorProperty, foregroundColorAnimation);
            }
        }
        
        private void TermsLink_Click(object sender, RoutedEventArgs e)
        {
            ShowTermsAndConditionsDialog();
        }
        
        private void ShowTermsAndConditionsDialog()
        {
            try
            {
                TermsDialog termsDialog = new TermsDialog();
                termsDialog.Owner = this;
                termsDialog.WindowStartupLocation = WindowStartupLocation.CenterOwner;
                
                // Estilo modal
                termsDialog.ShowDialog();
                
                // Si se aceptaron los términos en el diálogo
                if (termsDialog.TermsAccepted)
                {
                    AcceptTermsCheckBox.IsChecked = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error al mostrar términos y condiciones: {ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            ShowCancelConfirmationDialog();
        }
        
        private void ShowCancelConfirmationDialog()
        {
            MessageBoxResult result = MessageBox.Show(
                "¿Está seguro de que desea cancelar la instalación?",
                "Confirmar cancelación",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
                
            if (result == MessageBoxResult.Yes)
            {
                // Animar salida antes de cerrar
                AnimateExit(() =>
                {
                    Application.Current.Shutdown(0);
                });
            }
        }
        
        private void NextButton_Click(object sender, RoutedEventArgs e)
        {
            // Validar términos aceptados
            if (AcceptTermsCheckBox.IsChecked != true)
            {
                MessageBox.Show("Debe aceptar los términos y condiciones para continuar.",
                    "Términos no aceptados", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            
            // Navegar a la siguiente pantalla
            NavigateToTenantTokenScreen();
        }
        
        private void NavigateToTenantTokenScreen()
        {
            try
            {
                // Animar transición
                AnimateTransition(() =>
                {
                    // Crear y mostrar siguiente pantalla
                    TenantTokenScreen nextScreen = new TenantTokenScreen(_navigationService, _config);
                    
                    // Configurar nueva ventana
                    nextScreen.Owner = this.Owner;
                    nextScreen.WindowStartupLocation = WindowStartupLocation.CenterScreen;
                    
                    // Mostrar nueva ventana
                    nextScreen.Show();
                    
                    // Cerrar esta ventana
                    this.Close();
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error al navegar a la siguiente pantalla: {ex.Message}",
                    "Error de navegación", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        
        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            ShowCancelConfirmationDialog();
        }
        
        private void AnimateTransition(Action onCompleted)
        {
            // Animación de salida
            DoubleAnimation opacityAnimation = new DoubleAnimation
            {
                From = 1,
                To = 0,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            
            ScaleTransform scaleTransform = RenderTransform as ScaleTransform;
            if (scaleTransform == null)
            {
                scaleTransform = new ScaleTransform(1, 1);
                RenderTransform = scaleTransform;
                RenderTransformOrigin = new Point(0.5, 0.5);
            }
            
            DoubleAnimation scaleXAnimation = new DoubleAnimation
            {
                From = 1,
                To = 0.95,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            
            DoubleAnimation scaleYAnimation = new DoubleAnimation
            {
                From = 1,
                To = 0.95,
                Duration = TimeSpan.FromSeconds(0.3),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            
            // Configurar evento de completado
            opacityAnimation.Completed += (s, e) =>
            {
                onCompleted?.Invoke();
            };
            
            // Iniciar animaciones
            BeginAnimation(OpacityProperty, opacityAnimation);
            scaleTransform.BeginAnimation(ScaleTransform.ScaleXProperty, scaleXAnimation);
            scaleTransform.BeginAnimation(ScaleTransform.ScaleYProperty, scaleYAnimation);
        }
        
        private void AnimateExit(Action onCompleted)
        {
            // Animación similar a AnimateTransition pero con callback al finalizar
            AnimateTransition(onCompleted);
        }
        
        // Clase para verificar requisitos del sistema
        private class SystemRequirements
        {
            public bool IsWindowsVersionSupported()
            {
                var osVersion = Environment.OSVersion;
                var platform = osVersion.Platform;
                var version = osVersion.Version;
                
                return platform == PlatformID.Win32NT && 
                       version.Major >= 10 && 
                       version.Build >= 14393;
            }
            
            public bool Is64BitArchitecture()
            {
                return Environment.Is64BitOperatingSystem;
            }
            
            public bool IsRunningAsAdministrator()
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    var principal = new System.Security.Principal.WindowsPrincipal(identity);
                    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            
            public bool HasSufficientDiskSpace(long requiredSpace)
            {
                try
                {
                    string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
                    var driveInfo = new DriveInfo(systemDrive);
                    return driveInfo.AvailableFreeSpace > requiredSpace;
                }
                catch
                {
                    return false;
                }
            }
            
            public bool IsDotNetFrameworkInstalled()
            {
                try
                {
                    using (Microsoft.Win32.RegistryKey ndpKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                    {
                        if (ndpKey != null)
                        {
                            int releaseKey = (int)(ndpKey.GetValue("Release") ?? 0);
                            return releaseKey >= 528040; // .NET Framework 4.8
                        }
                    }
                    return false;
                }
                catch
                {
                    return false;
                }
            }
        }
    }
    
    // Clase para el diálogo de términos y condiciones
    public class TermsDialog : Window
    {
        public bool TermsAccepted { get; private set; }
        
        public TermsDialog()
        {
            InitializeComponent();
        }
        
        private void InitializeComponent()
        {
            Width = 800;
            Height = 600;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            WindowStyle = WindowStyle.SingleBorderWindow;
            ResizeMode = ResizeMode.NoResize;
            Title = "Términos y Condiciones - BWP Enterprise";
            
            // Contenido del diálogo
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            
            // Texto de términos
            var scrollViewer = new ScrollViewer();
            var textBlock = new TextBlock
            {
                Text = GetTermsAndConditionsText(),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(20),
                FontSize = 12
            };
            
            scrollViewer.Content = textBlock;
            Grid.SetRow(scrollViewer, 0);
            grid.Children.Add(scrollViewer);
            
            // Botones
            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(20)
            };
            
            var declineButton = new Button
            {
                Content = "No acepto",
                Width = 100,
                Margin = new Thickness(0, 0, 10, 0)
            };
            declineButton.Click += (s, e) => { TermsAccepted = false; Close(); };
            
            var acceptButton = new Button
            {
                Content = "Acepto",
                Width = 100,
                Background = new SolidColorBrush(Color.FromRgb(0, 120, 212)),
                Foreground = Brushes.White
            };
            acceptButton.Click += (s, e) => { TermsAccepted = true; Close(); };
            
            buttonPanel.Children.Add(declineButton);
            buttonPanel.Children.Add(acceptButton);
            
            Grid.SetRow(buttonPanel, 1);
            grid.Children.Add(buttonPanel);
            
            Content = grid;
        }
        
        private string GetTermsAndConditionsText()
        {
            return @"ACUERDO DE LICENCIA DE USUARIO FINAL
BWP ENTERPRISE SECURITY SUITE

IMPORTANTE: LEA ATENTAMENTE ESTE ACUERDO DE LICENCIA DE USUARIO FINAL (""EULA"") ANTES DE INSTALAR O UTILIZAR EL SOFTWARE. AL INSTALAR, COPIAR O UTILIZAR EL SOFTWARE, USTED ACEPTA QUEDAR OBLIGADO POR LOS TÉRMINOS DE ESTE EULA. SI NO ACEPTA LOS TÉRMINOS DE ESTE EULA, NO INSTALE NI UTILICE EL SOFTWARE.

1. DEFINICIONES
1.1. ""Software"" significa el programa de computadora BWP Enterprise Security Suite, incluyendo todos los componentes, módulos, actualizaciones y documentación asociada.
1.2. ""Licenciante"" significa BWP Technologies, propietario de los derechos de autor del Software.
1.3. ""Licenciatario"" significa la persona física o jurídica que adquiere la licencia para usar el Software.

2. CONCESIÓN DE LICENCIA
2.1. Sujeto al cumplimiento de los términos de este EULA, el Licenciante concede al Licenciatario una licencia no exclusiva, intransferible y limitada para:
   a) Instalar y usar el Software en los endpoints especificados en la licencia adquirida.
   b) Hacer copias de respaldo del Software únicamente con fines de archivo.

3. RESTRICCIONES
3.1. El Licenciatario NO podrá:
   a) Modificar, descompilar, desensamblar o realizar ingeniería inversa del Software.
   b) Distribuir, sublicenciar, alquilar, prestar o transferir el Software a terceros.
   c) Eliminar o alterar cualquier aviso de derechos de autor, marca registrada u otra notificación propietaria.
   d) Utilizar el Software para fines ilegales o no autorizados.

4. PROPIEDAD INTELECTUAL
4.1. El Software está protegido por las leyes de derechos de autor y otros tratados internacionales de propiedad intelectual.
4.2. Todos los derechos, títulos e intereses sobre el Software, incluyendo todos los derechos de propiedad intelectual, son y permanecerán propiedad exclusiva del Licenciante.

5. RECOLECCIÓN DE DATOS
5.1. El Software puede recolectar y transmitir datos relacionados con:
   a) Eventos de seguridad detectados en el endpoint.
   b) Información de configuración del sistema.
   c) Métricas de rendimiento y uso.
5.2. Los datos recolectados se utilizan únicamente para:
   a) Mejorar los servicios de seguridad.
   b) Generar reportes y análisis.
   c) Cumplir con obligaciones contractuales.

6. GARANTÍAS Y EXCLUSIÓN DE RESPONSABILIDAD
6.1. EL SOFTWARE SE PROPORCIONA ""TAL CUAL"" SIN GARANTÍAS DE NINGÚN TIPO.
6.2. EL LICENCIANTE NO GARANTIZA QUE EL SOFTWARE ESTÉ LIBRE DE ERRORES O QUE FUNCIONE ININTERRUMPIDAMENTE.
6.3. EN NINGÚN CASO EL LICENCIANTE SERÁ RESPONSABLE POR DAÑOS DIRECTOS, INDIRECTOS, INCIDENTALES O CONSECUENTES.

7. TERMINACIÓN
7.1. Este EULA entra en vigor en la fecha de instalación y continúa hasta su terminación.
7.2. El Licenciante puede terminar este EULA si el Licenciatario incumple cualquiera de sus términos.
7.3. Al terminar, el Licenciatario debe destruir todas las copias del Software.

8. LEY APLICABLE
8.1. Este EULA se rige por las leyes del país donde el Licenciante tiene su domicilio principal.

9. ACUERDO COMPLETO
9.1. Este EULA constituye el acuerdo completo entre las partes con respecto al Software.

AL HACER CLIC EN ""ACEPTO"" O AL INSTALAR EL SOFTWARE, USTED RECONOCE HABER LEÍDO, ENTENDIDO Y ACEPTADO LOS TÉRMINOS DE ESTE EULA.";
        }
    }
    
    // Servicio de navegación (simplificado)
    public class InstallerNavigationService
    {
        public void NavigateTo(string screenName, object parameter = null)
        {
            // Implementación de navegación entre pantallas
        }
    }
}