using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.Api
{
    /// <summary>
    /// Servicio de ingesta de CVEs desde la API de NVD (National Vulnerability Database)
    /// Maneja rate limiting, caching y normalización de datos
    /// </summary>
    public sealed class CveIngestionService : ICveIngestionService
    {
        private readonly ILogger<CveIngestionService> _logger;
        private readonly HttpClient _httpClient;
        private readonly ICveCacheRepository _cacheRepository;
        private readonly SemaphoreSlim _rateLimitSemaphore;
        private readonly Dictionary<string, DateTime> _lastFetchTimestamps;
        private readonly object _syncLock = new object();
        
        // Constantes de configuración
        private const string NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        private const int REQUESTS_PER_30_SECONDS = 30; // Límite de NVD
        private const int CACHE_DURATION_HOURS = 24;
        private const int RETRY_DELAY_MS = 5000;
        private const int MAX_RETRIES = 3;
        
        public CveIngestionService(
            ILogger<CveIngestionService> logger,
            HttpClient httpClient,
            ICveCacheRepository cacheRepository)
        {
            _logger = logger;
            _httpClient = httpClient;
            _cacheRepository = cacheRepository;
            _rateLimitSemaphore = new SemaphoreSlim(REQUESTS_PER_30_SECONDS, REQUESTS_PER_30_SECONDS);
            _lastFetchTimestamps = new Dictionary<string, DateTime>();
            
            ConfigureHttpClient();
        }
        
        private void ConfigureHttpClient()
        {
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            _httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd("BWP-Enterprise/1.0");
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
        }
        
        /// <summary>
        /// Obtiene CVEs para un software específico y versión
        /// </summary>
        public async Task<List<CveEntry>> GetCvesForSoftwareAsync(
            string softwareName, 
            string version,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(softwareName))
                throw new ArgumentException("Software name is required", nameof(softwareName));
            
            var cacheKey = $"{softwareName.ToLowerInvariant()}:{version?.ToLowerInvariant() ?? "any"}";
            
            try
            {
                // 1. Verificar cache primero
                var cachedResult = await _cacheRepository.GetCvesAsync(cacheKey);
                if (cachedResult != null && !IsCacheExpired(cacheKey))
                {
                    _logger.LogDebug("CVEs obtenidos de cache para {Software}:{Version}", 
                        softwareName, version);
                    return cachedResult;
                }
                
                // 2. Verificar rate limit
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
                try
                {
                    // 3. Consultar API de NVD
                    var cves = await FetchCvesFromNvdAsync(softwareName, version, cancellationToken);
                    
                    // 4. Actualizar cache
                    await _cacheRepository.SetCvesAsync(cacheKey, cves, TimeSpan.FromHours(CACHE_DURATION_HOURS));
                    UpdateFetchTimestamp(cacheKey);
                    
                    _logger.LogInformation("Obtenidos {Count} CVEs para {Software}:{Version} desde NVD", 
                        cves.Count, softwareName, version);
                    
                    return cves;
                }
                finally
                {
                    _rateLimitSemaphore.Release();
                    ScheduleRateLimitReset();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo CVEs para {Software}:{Version}", 
                    softwareName, version);
                throw new CveIngestionException($"Failed to fetch CVEs for {softwareName}: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Obtiene CVEs nuevos desde una fecha específica
        /// </summary>
        public async Task<List<CveEntry>> GetNewCvesSinceAsync(
            DateTime sinceDate,
            CancellationToken cancellationToken = default)
        {
            if (sinceDate > DateTime.UtcNow)
                throw new ArgumentException("Date cannot be in the future", nameof(sinceDate));
            
            try
            {
                var startIndex = 0;
                var resultsPerPage = 2000; // Máximo permitido por NVD
                var allCves = new List<CveEntry>();
                var totalResults = int.MaxValue;
                
                while (startIndex < totalResults)
                {
                    var url = $"{NVD_API_BASE_URL}?" +
                             $"lastModStartDate={sinceDate:yyyy-MM-ddTHH:mm:ss:fffZ}&" +
                             $"lastModEndDate={DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss:fffZ}&" +
                             $"startIndex={startIndex}&resultsPerPage={resultsPerPage}";
                    
                    await _rateLimitSemaphore.WaitAsync(cancellationToken);
                    
                    try
                    {
                        var response = await _httpClient.GetAsync(url, cancellationToken);
                        
                        if (!response.IsSuccessStatusCode)
                        {
                            if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                            {
                                _logger.LogWarning("Rate limit alcanzado, reintentando en {Delay}ms", RETRY_DELAY_MS);
                                await Task.Delay(RETRY_DELAY_MS, cancellationToken);
                                continue;
                            }
                            
                            throw new HttpRequestException($"NVD API returned {response.StatusCode}: {response.ReasonPhrase}");
                        }
                        
                        var json = await response.Content.ReadAsStringAsync(cancellationToken);
                        var nvdResponse = JsonSerializer.Deserialize<NvdResponse>(json, new JsonSerializerOptions
                        {
                            PropertyNameCaseInsensitive = true
                        });
                        
                        if (nvdResponse == null)
                            break;
                        
                        totalResults = nvdResponse.TotalResults;
                        var cves = nvdResponse.Vulnerabilities
                            .Select(v => v.Cve)
                            .Select(ConvertNvdCveToEntry)
                            .Where(c => c != null)
                            .ToList();
                        
                        allCves.AddRange(cves);
                        startIndex += resultsPerPage;
                        
                        _logger.LogDebug("Obtenidos {Count} CVEs nuevos desde {SinceDate}", 
                            cves.Count, sinceDate);
                    }
                    finally
                    {
                        _rateLimitSemaphore.Release();
                        ScheduleRateLimitReset();
                    }
                    
                    // Pequeña pausa para no sobrecargar la API
                    await Task.Delay(100, cancellationToken);
                }
                
                return allCves;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo CVEs nuevos desde {SinceDate}", sinceDate);
                throw new CveIngestionException($"Failed to fetch new CVEs: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Busca CVEs por CPE (Common Platform Enumeration)
        /// </summary>
        public async Task<List<CveEntry>> SearchCvesByCpeAsync(
            string cpeString,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(cpeString))
                throw new ArgumentException("CPE string is required", nameof(cpeString));
            
            try
            {
                // Codificar CPE para URL
                var encodedCpe = Uri.EscapeDataString(cpeString);
                var url = $"{NVD_API_BASE_URL}?cpeName={encodedCpe}";
                
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
                
                try
                {
                    var response = await _httpClient.GetAsync(url, cancellationToken);
                    response.EnsureSuccessStatusCode();
                    
                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    var nvdResponse = JsonSerializer.Deserialize<NvdResponse>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    
                    var cves = nvdResponse?.Vulnerabilities
                        .Select(v => v.Cve)
                        .Select(ConvertNvdCveToEntry)
                        .Where(c => c != null)
                        .ToList() ?? new List<CveEntry>();
                    
                    return cves;
                }
                finally
                {
                    _rateLimitSemaphore.Release();
                    ScheduleRateLimitReset();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error buscando CVEs por CPE: {Cpe}", cpeString);
                throw new CveIngestionException($"Failed to search CVEs by CPE: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Obtiene detalles específicos de un CVE
        /// </summary>
        public async Task<CveEntry> GetCveDetailsAsync(
            string cveId,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(cveId) || !cveId.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Invalid CVE ID format", nameof(cveId));
            
            try
            {
                var cacheKey = $"cve:{cveId.ToUpperInvariant()}";
                
                // Verificar cache
                var cachedCve = await _cacheRepository.GetCveAsync(cveId);
                if (cachedCve != null)
                {
                    return cachedCve;
                }
                
                var url = $"{NVD_API_BASE_URL}?cveId={cveId}";
                
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
                
                try
                {
                    var response = await _httpClient.GetAsync(url, cancellationToken);
                    response.EnsureSuccessStatusCode();
                    
                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    var nvdResponse = JsonSerializer.Deserialize<NvdResponse>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    
                    var nvdCve = nvdResponse?.Vulnerabilities.FirstOrDefault()?.Cve;
                    if (nvdCve == null)
                    {
                        throw new CveNotFoundException($"CVE {cveId} not found in NVD");
                    }
                    
                    var cveEntry = ConvertNvdCveToEntry(nvdCve);
                    
                    // Cachear resultado
                    await _cacheRepository.SetCveAsync(cveId, cveEntry, TimeSpan.FromHours(CACHE_DURATION_HOURS));
                    
                    return cveEntry;
                }
                finally
                {
                    _rateLimitSemaphore.Release();
                    ScheduleRateLimitReset();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo detalles de CVE: {CveId}", cveId);
                throw new CveIngestionException($"Failed to fetch CVE details: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Obtiene el impacto CVSS de un CVE
        /// </summary>
        public async Task<CvssImpact> GetCvssImpactAsync(
            string cveId,
            CancellationToken cancellationToken = default)
        {
            var cveEntry = await GetCveDetailsAsync(cveId, cancellationToken);
            
            // Extraer la métrica CVSS más reciente
            var cvssMetric = cveEntry.CvssMetrics
                .OrderByDescending(m => m.Version)
                .ThenByDescending(m => m.Score)
                .FirstOrDefault();
            
            if (cvssMetric == null)
            {
                return new CvssImpact
                {
                    BaseScore = 0.0,
                    Severity = "UNKNOWN",
                    VectorString = "N/A"
                };
            }
            
            return cvssMetric;
        }
        
        /// <summary>
        /// Programa una actualización diaria de CVEs
        /// </summary>
        public void ScheduleDailyUpdate(TimeSpan timeOfDay)
        {
            var now = DateTime.Now;
            var scheduledTime = now.Date.Add(timeOfDay);
            
            if (scheduledTime < now)
            {
                scheduledTime = scheduledTime.AddDays(1);
            }
            
            var delay = scheduledTime - now;
            
            _ = Task.Run(async () =>
            {
                await Task.Delay(delay);
                await PerformScheduledUpdateAsync();
                
                // Programar siguiente actualización
                ScheduleDailyUpdate(timeOfDay);
            });
        }
        
        /// <summary>
        /// Actualiza el cache con los CVEs más recientes
        /// </summary>
        public async Task<bool> RefreshCacheAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                _logger.LogInformation("Iniciando actualización de cache de CVEs");
                
                // Obtener CVEs de las últimas 24 horas
                var yesterday = DateTime.UtcNow.AddDays(-1);
                var newCves = await GetNewCvesSinceAsync(yesterday, cancellationToken);
                
                // Actualizar cache para cada CVE
                foreach (var cve in newCves)
                {
                    await _cacheRepository.SetCveAsync(cve.Id, cve, TimeSpan.FromDays(7));
                }
                
                // Actualizar cache de software conocido
                await UpdateKnownSoftwareCacheAsync(cancellationToken);
                
                _logger.LogInformation("Cache actualizado con {Count} CVEs nuevos", newCves.Count);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando cache de CVEs");
                return false;
            }
        }
        
        private async Task<List<CveEntry>> FetchCvesFromNvdAsync(
            string softwareName,
            string version,
            CancellationToken cancellationToken)
        {
            var retryCount = 0;
            
            while (retryCount < MAX_RETRIES)
            {
                try
                {
                    var keyword = $"{softwareName} {version}".Trim();
                    var encodedKeyword = Uri.EscapeDataString(keyword);
                    var url = $"{NVD_API_BASE_URL}?keywordSearch={encodedKeyword}&keywordExactMatch";
                    
                    var response = await _httpClient.GetAsync(url, cancellationToken);
                    
                    if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                    {
                        retryCount++;
                        var delay = RETRY_DELAY_MS * retryCount;
                        _logger.LogWarning("Rate limit, reintento {Retry}/{MaxRetries} en {Delay}ms", 
                            retryCount, MAX_RETRIES, delay);
                        await Task.Delay(delay, cancellationToken);
                        continue;
                    }
                    
                    response.EnsureSuccessStatusCode();
                    
                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    var nvdResponse = JsonSerializer.Deserialize<NvdResponse>(json, new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    });
                    
                    if (nvdResponse == null || nvdResponse.Vulnerabilities == null)
                    {
                        return new List<CveEntry>();
                    }
                    
                    // Filtrar por versión específica si se proporcionó
                    var cves = nvdResponse.Vulnerabilities
                        .Select(v => v.Cve)
                        .Select(ConvertNvdCveToEntry)
                        .Where(c => c != null)
                        .ToList();
                    
                    if (!string.IsNullOrEmpty(version))
                    {
                        cves = cves.Where(c => 
                            c.AffectedSoftware?.Any(s => 
                                s.Name.Equals(softwareName, StringComparison.OrdinalIgnoreCase) &&
                                (string.IsNullOrEmpty(version) || 
                                 s.Versions.Any(v => IsVersionAffected(version, v))))
                            ?? false)
                            .ToList();
                    }
                    
                    return cves;
                }
                catch (HttpRequestException ex) when (retryCount < MAX_RETRIES - 1)
                {
                    retryCount++;
                    _logger.LogWarning(ex, "Error HTTP, reintento {Retry}/{MaxRetries}", 
                        retryCount, MAX_RETRIES);
                    await Task.Delay(RETRY_DELAY_MS * retryCount, cancellationToken);
                }
            }
            
            throw new CveIngestionException($"Failed to fetch CVEs after {MAX_RETRIES} retries");
        }
        
        private CveEntry ConvertNvdCveToEntry(NvdCve nvdCve)
        {
            if (nvdCve == null) return null;
            
            var cveEntry = new CveEntry
            {
                Id = nvdCve.Id,
                Description = nvdCve.Descriptions
                    .FirstOrDefault(d => d.Lang == "en")?.Value ?? "No description available",
                Published = DateTime.TryParse(nvdCve.Published, out var published) ? published : DateTime.MinValue,
                LastModified = DateTime.TryParse(nvdCve.LastModified, out var lastModified) ? lastModified : DateTime.MinValue,
                SourceIdentifier = nvdCve.SourceIdentifier,
                VulnStatus = nvdCve.VulnStatus
            };
            
            // Extraer métricas CVSS
            if (nvdCve.Metrics != null)
            {
                cveEntry.CvssMetrics = new List<CvssImpact>();
                
                if (nvdCve.Metrics.CvssMetricV31 != null)
                {
                    foreach (var metric in nvdCve.Metrics.CvssMetricV31)
                    {
                        cveEntry.CvssMetrics.Add(new CvssImpact
                        {
                            Version = "3.1",
                            Source = metric.Source,
                            Type = metric.Type,
                            BaseScore = metric.CvssData.BaseScore,
                            Severity = metric.CvssData.BaseSeverity,
                            VectorString = metric.CvssData.VectorString,
                            ExploitabilityScore = metric.ExploitabilityScore,
                            ImpactScore = metric.ImpactScore
                        });
                    }
                }
                
                if (nvdCve.Metrics.CvssMetricV30 != null)
                {
                    foreach (var metric in nvdCve.Metrics.CvssMetricV30)
                    {
                        cveEntry.CvssMetrics.Add(new CvssImpact
                        {
                            Version = "3.0",
                            Source = metric.Source,
                            Type = metric.Type,
                            BaseScore = metric.CvssData.BaseScore,
                            Severity = metric.CvssData.BaseSeverity,
                            VectorString = metric.CvssData.VectorString,
                            ExploitabilityScore = metric.ExploitabilityScore,
                            ImpactScore = metric.ImpactScore
                        });
                    }
                }
                
                if (nvdCve.Metrics.CvssMetricV2 != null)
                {
                    foreach (var metric in nvdCve.Metrics.CvssMetricV2)
                    {
                        cveEntry.CvssMetrics.Add(new CvssImpact
                        {
                            Version = "2.0",
                            Source = metric.Source,
                            Type = metric.Type,
                            BaseScore = metric.CvssData.BaseScore,
                            Severity = GetSeverityFromCvss2(metric.CvssData.BaseScore),
                            VectorString = metric.CvssData.VectorString,
                            ExploitabilityScore = metric.ExploitabilityScore,
                            ImpactScore = metric.ImpactScore
                        });
                    }
                }
            }
            
            // Extraer software afectado
            if (nvdCve.Configurations != null)
            {
                cveEntry.AffectedSoftware = new List<AffectedSoftware>();
                
                foreach (var config in nvdCve.Configurations)
                {
                    foreach (var node in config.Nodes)
                    {
                        foreach (var cpeMatch in node.CpeMatch)
                        {
                            var software = ParseCpeString(cpeMatch.Criteria);
                            if (software != null)
                            {
                                software.Versions = cpeMatch.VersionEndExcluding != null ? 
                                    new List<string> { $"< {cpeMatch.VersionEndExcluding}" } :
                                    cpeMatch.VersionEndIncluding != null ? 
                                    new List<string> { $"<= {cpeMatch.VersionEndIncluding}" } :
                                    cpeMatch.VersionStartIncluding != null ? 
                                    new List<string> { $">= {cpeMatch.VersionStartIncluding}" } :
                                    new List<string>();
                                
                                cveEntry.AffectedSoftware.Add(software);
                            }
                        }
                    }
                }
            }
            
            // Extraer referencias
            if (nvdCve.References != null)
            {
                cveEntry.References = nvdCve.References
                    .Select(r => new CveReference
                    {
                        Url = r.Url,
                        Source = r.Source,
                        Tags = r.Tags ?? new List<string>()
                    })
                    .ToList();
            }
            
            // Determinar severidad basada en CVSS
            cveEntry.Severity = DetermineOverallSeverity(cveEntry.CvssMetrics);
            
            return cveEntry;
        }
        
        private string GetSeverityFromCvss2(double score)
        {
            return score switch
            {
                >= 7.0 => "HIGH",
                >= 4.0 => "MEDIUM",
                > 0.0 => "LOW",
                _ => "NONE"
            };
        }
        
        private string DetermineOverallSeverity(List<CvssImpact> metrics)
        {
            if (metrics == null || metrics.Count == 0)
                return "UNKNOWN";
            
            var highestMetric = metrics
                .OrderByDescending(m => m.Version)
                .ThenByDescending(m => m.BaseScore)
                .First();
            
            return highestMetric.Severity ?? "UNKNOWN";
        }
        
        private AffectedSoftware ParseCpeString(string cpe)
        {
            try
            {
                // Formato: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
                var parts = cpe.Split(':');
                if (parts.Length < 6) return null;
                
                return new AffectedSoftware
                {
                    Vendor = parts.Length > 3 ? parts[3] : null,
                    Name = parts.Length > 4 ? parts[4] : null,
                    Version = parts.Length > 5 ? parts[5] : null,
                    CpeString = cpe
                };
            }
            catch
            {
                return null;
            }
        }
        
        private bool IsVersionAffected(string installedVersion, string affectedVersionRange)
        {
            // Lógica simplificada para determinar si una versión está afectada
            // En producción, implementar lógica completa de comparación de versiones
            if (string.IsNullOrEmpty(affectedVersionRange) || affectedVersionRange == "*")
                return true;
            
            if (affectedVersionRange.StartsWith("<="))
            {
                var maxVersion = affectedVersionRange.Substring(3).Trim();
                return CompareVersions(installedVersion, maxVersion) <= 0;
            }
            else if (affectedVersionRange.StartsWith("<"))
            {
                var maxVersion = affectedVersionRange.Substring(2).Trim();
                return CompareVersions(installedVersion, maxVersion) < 0;
            }
            else if (affectedVersionRange.StartsWith(">="))
            {
                var minVersion = affectedVersionRange.Substring(3).Trim();
                return CompareVersions(installedVersion, minVersion) >= 0;
            }
            else if (affectedVersionRange.StartsWith(">"))
            {
                var minVersion = affectedVersionRange.Substring(2).Trim();
                return CompareVersions(installedVersion, minVersion) > 0;
            }
            
            // Versión exacta
            return installedVersion == affectedVersionRange;
        }
        
        private int CompareVersions(string version1, string version2)
        {
            // Implementación básica de comparación de versiones
            var v1 = version1.Split('.', '-');
            var v2 = version2.Split('.', '-');
            
            for (int i = 0; i < Math.Max(v1.Length, v2.Length); i++)
            {
                var part1 = i < v1.Length ? v1[i] : "0";
                var part2 = i < v2.Length ? v2[i] : "0";
                
                if (int.TryParse(part1, out var num1) && int.TryParse(part2, out var num2))
                {
                    if (num1 != num2) return num1.CompareTo(num2);
                }
                else
                {
                    var strCompare = string.Compare(part1, part2, StringComparison.Ordinal);
                    if (strCompare != 0) return strCompare;
                }
            }
            
            return 0;
        }
        
        private bool IsCacheExpired(string cacheKey)
        {
            lock (_syncLock)
            {
                if (!_lastFetchTimestamps.TryGetValue(cacheKey, out var lastFetch))
                    return true;
                
                return DateTime.UtcNow - lastFetch > TimeSpan.FromHours(CACHE_DURATION_HOURS);
            }
        }
        
        private void UpdateFetchTimestamp(string cacheKey)
        {
            lock (_syncLock)
            {
                _lastFetchTimestamps[cacheKey] = DateTime.UtcNow;
                
                // Limpiar entradas antiguas
                var oldKeys = _lastFetchTimestamps
                    .Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromHours(CACHE_DURATION_HOURS * 2))
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var key in oldKeys)
                {
                    _lastFetchTimestamps.Remove(key);
                }
            }
        }
        
        private async Task UpdateKnownSoftwareCacheAsync(CancellationToken cancellationToken)
        {
            // Lista de software comúnmente monitoreado
            var commonSoftware = new[]
            {
                "windows", "office", "chrome", "firefox", "edge", "java",
                "adobe reader", "flash", "vnc", "teamviewer", "anydesk"
            };
            
            foreach (var software in commonSoftware)
            {
                try
                {
                    await GetCvesForSoftwareAsync(software, null, cancellationToken);
                    await Task.Delay(100, cancellationToken); // Respetar rate limit
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error actualizando cache para {Software}", software);
                }
            }
        }
        
        private async Task PerformScheduledUpdateAsync()
        {
            try
            {
                _logger.LogInformation("Ejecutando actualización programada de CVEs");
                
                var success = await RefreshCacheAsync();
                
                if (success)
                {
                    _logger.LogInformation("Actualización programada completada exitosamente");
                }
                else
                {
                    _logger.LogWarning("Actualización programada falló");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en actualización programada de CVEs");
            }
        }
        
        private void ScheduleRateLimitReset()
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(30));
                
                lock (_syncLock)
                {
                    // Resetear semáforo cada 30 segundos
                    var currentCount = _rateLimitSemaphore.CurrentCount;
                    if (currentCount < REQUESTS_PER_30_SECONDS)
                    {
                        _rateLimitSemaphore.Release(REQUESTS_PER_30_SECONDS - currentCount);
                    }
                }
            });
        }
    }
    
    #region Modelos de datos
    
    public interface ICveIngestionService
    {
        Task<List<CveEntry>> GetCvesForSoftwareAsync(string softwareName, string version, CancellationToken cancellationToken = default);
        Task<List<CveEntry>> GetNewCvesSinceAsync(DateTime sinceDate, CancellationToken cancellationToken = default);
        Task<List<CveEntry>> SearchCvesByCpeAsync(string cpeString, CancellationToken cancellationToken = default);
        Task<CveEntry> GetCveDetailsAsync(string cveId, CancellationToken cancellationToken = default);
        Task<CvssImpact> GetCvssImpactAsync(string cveId, CancellationToken cancellationToken = default);
        Task<bool> RefreshCacheAsync(CancellationToken cancellationToken = default);
        void ScheduleDailyUpdate(TimeSpan timeOfDay);
    }
    
    public class CveEntry
    {
        public string Id { get; set; } // CVE-2024-XXXXX
        public string Description { get; set; }
        public DateTime Published { get; set; }
        public DateTime LastModified { get; set; }
        public string SourceIdentifier { get; set; }
        public string VulnStatus { get; set; }
        public string Severity { get; set; } // CRITICAL, HIGH, MEDIUM, LOW
        public List<CvssImpact> CvssMetrics { get; set; }
        public List<AffectedSoftware> AffectedSoftware { get; set; }
        public List<CveReference> References { get; set; }
        
        public CveEntry()
        {
            CvssMetrics = new List<CvssImpact>();
            AffectedSoftware = new List<AffectedSoftware>();
            References = new List<CveReference>();
        }
    }
    
    public class CvssImpact
    {
        public string Version { get; set; } // "2.0", "3.0", "3.1"
        public string Source { get; set; }
        public string Type { get; set; } // "Primary", "Secondary"
        public double BaseScore { get; set; }
        public string Severity { get; set; } // CRITICAL, HIGH, MEDIUM, LOW
        public string VectorString { get; set; }
        public double? ExploitabilityScore { get; set; }
        public double? ImpactScore { get; set; }
    }
    
    public class AffectedSoftware
    {
        public string Vendor { get; set; }
        public string Name { get; set; }
        public string Version { get; set; }
        public string CpeString { get; set; }
        public List<string> Versions { get; set; }
        
        public AffectedSoftware()
        {
            Versions = new List<string>();
        }
    }
    
    public class CveReference
    {
        public string Url { get; set; }
        public string Source { get; set; }
        public List<string> Tags { get; set; }
    }
    
    // Modelos para deserialización de respuesta NVD
    public class NvdResponse
    {
        public int TotalResults { get; set; }
        public List<NvdVulnerability> Vulnerabilities { get; set; }
    }
    
    public class NvdVulnerability
    {
        public NvdCve Cve { get; set; }
    }
    
    public class NvdCve
    {
        public string Id { get; set; }
        public List<NvdDescription> Descriptions { get; set; }
        public string Published { get; set; }
        public string LastModified { get; set; }
        public string SourceIdentifier { get; set; }
        public string VulnStatus { get; set; }
        public NvdMetrics Metrics { get; set; }
        public List<NvdConfiguration> Configurations { get; set; }
        public List<NvdReference> References { get; set; }
    }
    
    public class NvdDescription
    {
        public string Lang { get; set; }
        public string Value { get; set; }
    }
    
    public class NvdMetrics
    {
        public List<CvssMetricV31> CvssMetricV31 { get; set; }
        public List<CvssMetricV30> CvssMetricV30 { get; set; }
        public List<CvssMetricV2> CvssMetricV2 { get; set; }
    }
    
    public class CvssMetricV31
    {
        public string Source { get; set; }
        public string Type { get; set; }
        public CvssDataV31 CvssData { get; set; }
        public double ExploitabilityScore { get; set; }
        public double ImpactScore { get; set; }
    }
    
    public class CvssDataV31
    {
        public string Version { get; set; }
        public double BaseScore { get; set; }
        public string BaseSeverity { get; set; }
        public string VectorString { get; set; }
    }
    
    public class CvssMetricV30
    {
        public string Source { get; set; }
        public string Type { get; set; }
        public CvssDataV30 CvssData { get; set; }
        public double ExploitabilityScore { get; set; }
        public double ImpactScore { get; set; }
    }
    
    public class CvssDataV30
    {
        public string Version { get; set; }
        public double BaseScore { get; set; }
        public string BaseSeverity { get; set; }
        public string VectorString { get; set; }
    }
    
    public class CvssMetricV2
    {
        public string Source { get; set; }
        public string Type { get; set; }
        public CvssDataV2 CvssData { get; set; }
        public double ExploitabilityScore { get; set; }
        public double ImpactScore { get; set; }
    }
    
    public class CvssDataV2
    {
        public string Version { get; set; }
        public double BaseScore { get; set; }
        public string AccessVector { get; set; }
        public string AccessComplexity { get; set; }
        public string Authentication { get; set; }
        public string ConfidentialityImpact { get; set; }
        public string IntegrityImpact { get; set; }
        public string AvailabilityImpact { get; set; }
        public string VectorString { get; set; }
    }
    
    public class NvdConfiguration
    {
        public List<NvdNode> Nodes { get; set; }
    }
    
    public class NvdNode
    {
        public List<NvdCpeMatch> CpeMatch { get; set; }
    }
    
    public class NvdCpeMatch
    {
        public string Criteria { get; set; }
        public string VersionStartIncluding { get; set; }
        public string VersionStartExcluding { get; set; }
        public string VersionEndIncluding { get; set; }
        public string VersionEndExcluding { get; set; }
    }
    
    public class NvdReference
    {
        public string Url { get; set; }
        public string Source { get; set; }
        public List<string> Tags { get; set; }
    }
    
    public interface ICveCacheRepository
    {
        Task<List<CveEntry>> GetCvesAsync(string cacheKey);
        Task SetCvesAsync(string cacheKey, List<CveEntry> cves, TimeSpan expiration);
        Task<CveEntry> GetCveAsync(string cveId);
        Task SetCveAsync(string cveId, CveEntry cve, TimeSpan expiration);
    }
    
    public class CveIngestionException : Exception
    {
        public CveIngestionException(string message) : base(message) { }
        public CveIngestionException(string message, Exception innerException) : base(message, innerException) { }
    }
    
    public class CveNotFoundException : Exception
    {
        public CveNotFoundException(string message) : base(message) { }
    }
    
    #endregion
}