using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using BWP.Enterprise.Agent.Core;

namespace BWP.Enterprise.Agent.UI.Converters
{
    /// <summary>
    /// Convierte severidad de amenaza a color
    /// </summary>
    public class SeverityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ThreatSeverity severity)
            {
                return severity switch
                {
                    ThreatSeverity.Critical => new SolidColorBrush(Color.FromRgb(244, 67, 54)),   // Rojo
                    ThreatSeverity.High => new SolidColorBrush(Color.FromRgb(255, 152, 0)),       // Naranja
                    ThreatSeverity.Medium => new SolidColorBrush(Color.FromRgb(255, 193, 7)),     // Amarillo
                    ThreatSeverity.Low => new SolidColorBrush(Color.FromRgb(76, 175, 80)),        // Verde
                    ThreatSeverity.Info => new SolidColorBrush(Color.FromRgb(33, 150, 243)),      // Azul
                    _ => new SolidColorBrush(Color.FromRgb(158, 158, 158))                        // Gris
                };
            }
            
            return new SolidColorBrush(Colors.Gray);
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte estado de módulo a color
    /// </summary>
    public class StatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string status)
            {
                return status.ToUpperInvariant() switch
                {
                    "ACTIVE" or "RUNNING" or "HEALTHY" => new SolidColorBrush(Colors.LimeGreen),
                    "INACTIVE" or "STOPPED" => new SolidColorBrush(Colors.Gray),
                    "DEGRADED" or "WARNING" => new SolidColorBrush(Colors.Orange),
                    "ERROR" or "UNHEALTHY" => new SolidColorBrush(Colors.Red),
                    _ => new SolidColorBrush(Colors.Yellow)
                };
            }
            
            return new SolidColorBrush(Colors.Gray);
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte nivel de riesgo a color
    /// </summary>
    public class RiskLevelToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string riskLevel)
            {
                return riskLevel.ToUpperInvariant() switch
                {
                    "CRITICAL" => new SolidColorBrush(Color.FromRgb(244, 67, 54)),   // Rojo
                    "HIGH" => new SolidColorBrush(Color.FromRgb(255, 152, 0)),       // Naranja
                    "MEDIUM" => new SolidColorBrush(Color.FromRgb(255, 193, 7)),     // Amarillo
                    "LOW" => new SolidColorBrush(Color.FromRgb(76, 175, 80)),        // Verde
                    "MINIMAL" => new SolidColorBrush(Color.FromRgb(33, 150, 243)),   // Azul
                    _ => new SolidColorBrush(Color.FromRgb(158, 158, 158))           // Gris
                };
            }
            
            return new SolidColorBrush(Colors.Gray);
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte estado de alerta a color
    /// </summary>
    public class AlertStatusToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is AlertStatus status)
            {
                return status switch
                {
                    AlertStatus.Active => new SolidColorBrush(Color.FromRgb(244, 67, 54)),     // Rojo
                    AlertStatus.Acknowledged => new SolidColorBrush(Color.FromRgb(255, 193, 7)), // Amarillo
                    AlertStatus.Resolved => new SolidColorBrush(Color.FromRgb(76, 175, 80)),    // Verde
                    AlertStatus.FalsePositive => new SolidColorBrush(Color.FromRgb(158, 158, 158)), // Gris
                    _ => new SolidColorBrush(Colors.Gray)
                };
            }
            
            return new SolidColorBrush(Colors.Gray);
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte booleano a visibilidad
    /// </summary>
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool boolValue)
            {
                // Si se pasa un parámetro "inverse", invertir la lógica
                if (parameter is string param && param.ToLowerInvariant() == "inverse")
                {
                    return boolValue ? Visibility.Collapsed : Visibility.Visible;
                }
                
                return boolValue ? Visibility.Visible : Visibility.Collapsed;
            }
            
            return Visibility.Collapsed;
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Formatea bytes a tamaño legible
    /// </summary>
    public class BytesToSizeConverter : IValueConverter
    {
        private static readonly string[] SizeSuffixes = { "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB" };
        
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is long bytes)
            {
                return FormatBytes(bytes);
            }
            
            if (value is int intBytes)
            {
                return FormatBytes(intBytes);
            }
            
            return "0 B";
        }
        
        private string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";
            
            var mag = (int)Math.Log(Math.Abs(bytes), 1024);
            var adjustedSize = bytes / Math.Pow(1024, mag);
            
            return $"{adjustedSize:0.##} {SizeSuffixes[mag]}";
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte timestamp a tiempo relativo
    /// </summary>
    public class TimeAgoConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is DateTime dateTime)
            {
                var timeSpan = DateTime.Now - dateTime;
                
                if (timeSpan.TotalDays >= 1)
                {
                    return $"{(int)timeSpan.TotalDays}d ago";
                }
                else if (timeSpan.TotalHours >= 1)
                {
                    return $"{(int)timeSpan.TotalHours}h ago";
                }
                else if (timeSpan.TotalMinutes >= 1)
                {
                    return $"{(int)timeSpan.TotalMinutes}m ago";
                }
                else
                {
                    return $"{(int)timeSpan.TotalSeconds}s ago";
                }
            }
            
            return "Unknown";
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
    
    /// <summary>
    /// Convierte porcentaje a color de progreso
    /// </summary>
    public class PercentageToProgressColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int percentage)
            {
                if (percentage >= 80)
                    return new SolidColorBrush(Color.FromRgb(244, 67, 54));   // Rojo
                else if (percentage >= 60)
                    return new SolidColorBrush(Color.FromRgb(255, 152, 0));   // Naranja
                else if (percentage >= 40)
                    return new SolidColorBrush(Color.FromRgb(255, 193, 7));   // Amarillo
                else
                    return new SolidColorBrush(Color.FromRgb(76, 175, 80));   // Verde
            }
            
            return new SolidColorBrush(Colors.Gray);
        }
        
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}