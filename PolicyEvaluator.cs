using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using BWP.Enterprise.Agent.Logging;
using BWP.Enterprise.Agent.Sensors;

namespace BWP.Enterprise.Agent.Policy
{
    /// <summary>
    /// Evaluador de políticas en tiempo real
    /// Evalúa eventos contra políticas activas y determina acciones
    /// </summary>
    public sealed class PolicyEvaluator : IAgentModule, IHealthCheckable
    {
        private static readonly Lazy<PolicyEvaluator> _instance = 
            new Lazy<PolicyEvaluator>(() => new PolicyEvaluator());
        
        public static PolicyEvaluator Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly PolicyManager _policyManager;
        private readonly ConcurrentDictionary<string, PolicyEvaluationCache> _evaluationCache;
        private readonly ConcurrentDictionary<string, DateTime> _policyChangeTimestamps;
        private bool _isInitialized;
        private bool _isRunning;
        private const int CACHE_SIZE = 10000;
        private const int CACHE_TTL_MINUTES = 5;
        
        public string ModuleId => "PolicyEvaluator";
        public string Version => "1.0.0";
        public string Description => "Evaluador de políticas en tiempo real";
        
        private PolicyEvaluator()
        {
            _logManager = LogManager.Instance;
            _policyManager = PolicyManager.Instance;
            _evaluationCache = new ConcurrentDictionary<string, PolicyEvaluationCache>();
            _policyChangeTimestamps = new ConcurrentDictionary<string, DateTime>();
            _isInitialized = false;
            _isRunning = false;
        }
        
        /// <summary>
        /// Inicializa el evaluador de políticas
        /// </summary>
        public async Task<ModuleOperationResult> InitializeAsync()
        {
            try
            {
                _logManager.LogInfo("Inicializando PolicyEvaluator...", ModuleId);
                
                // 1. Inicializar caché
                InitializeEvaluationCache();
                
                // 2. Configurar limpieza periódica de caché
                SetupCacheCleanup();
                
                // 3. Verificar integración con PolicyManager
                await VerifyPolicyManagerIntegrationAsync();
                
                _isInitialized = true;
                _logManager.LogInfo("PolicyEvaluator inicializado", ModuleId);
                
                return ModuleOperationResult.SuccessResult();
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error al inicializar PolicyEvaluator: {ex}", ModuleId);
                return ModuleOperationResult.ErrorResult(ex.Message);
            }
        }
        
        /// <summary>
        /// Evalúa un evento contra políticas activas
        /// </summary>
        public async Task<PolicyEvaluationResult> EvaluateEventAsync(SensorEvent sensorEvent)
        {
            if (!_isInitialized || sensorEvent == null)
            {
                return PolicyEvaluationResult.Error("PolicyEvaluator no inicializado o evento nulo");
            }
            
            try
            {
                // Verificar caché primero
                var cacheKey = GenerateCacheKey(sensorEvent);
                if (_evaluationCache.TryGetValue(cacheKey, out var cachedResult) && 
                    !IsCacheExpired(cachedResult))
                {
                    _logManager.LogDebug($"Resultado de evaluación obtenido de caché para evento {sensorEvent.EventId}", ModuleId);
                    return cachedResult.Result;
                }
                
                // Obtener políticas aplicables
                var applicablePolicies = await _policyManager.GetApplicablePoliciesAsync(sensorEvent);
                
                if (!applicablePolicies.Any())
                {
                    var noPolicyResult = PolicyEvaluationResult.NoPolicyApplicable(sensorEvent.EventId);
                    CacheEvaluationResult(cacheKey, noPolicyResult, sensorEvent);
                    return noPolicyResult;
                }
                
                // Evaluar contra cada política
                var evaluationResult = await EvaluateAgainstPoliciesAsync(sensorEvent, applicablePolicies);
                
                // Cachear resultado
                CacheEvaluationResult(cacheKey, evaluationResult, sensorEvent);
                
                return evaluationResult;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error evaluando evento {sensorEvent.EventId}: {ex}", ModuleId);
                return PolicyEvaluationResult.Error($"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Evalúa un evento específico contra una política específica
        /// </summary>
        public async Task<SinglePolicyEvaluationResult> EvaluateAgainstPolicyAsync(
            SensorEvent sensorEvent, 
            SecurityPolicy policy)
        {
            try
            {
                _logManager.LogDebug($"Evaluando evento {sensorEvent.EventId} contra política {policy.Name}", ModuleId);
                
                var result = new SinglePolicyEvaluationResult
                {
                    PolicyId = policy.PolicyId,
                    PolicyName = policy.Name,
                    EventId = sensorEvent.EventId,
                    Timestamp = DateTime.UtcNow,
                    ApplicableRules = new List<PolicyRuleEvaluationResult>()
                };
                
                // Verificar si la política aplica al evento
                if (!await PolicyAppliesToEventAsync(policy, sensorEvent))
                {
                    result.IsApplicable = false;
                    result.Decision = PolicyDecision.NotApplicable;
                    result.Message = "Política no aplicable a este evento";
                    return result;
                }
                
                result.IsApplicable = true;
                
                // Evaluar condiciones de la política
                var conditionsMet = await EvaluatePolicyConditionsAsync(policy, sensorEvent);
                if (!conditionsMet)
                {
                    result.Decision = PolicyDecision.ConditionsNotMet;
                    result.Message = "Condiciones de política no cumplidas";
                    return result;
                }
                
                // Evaluar cada regla de la política
                var ruleResults = await EvaluatePolicyRulesAsync(policy, sensorEvent);
                result.ApplicableRules = ruleResults;
                
                // Determinar decisión basada en resultados de reglas
                result.Decision = DeterminePolicyDecision(ruleResults);
                result.Message = $"Política evaluada: {result.Decision}";
                
                // Registrar métricas
                await RecordEvaluationMetricsAsync(result);
                
                return result;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error evaluando contra política {policy.PolicyId}: {ex}", ModuleId);
                return SinglePolicyEvaluationResult.Error(policy.PolicyId, $"Error: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Evalúa múltiples eventos en batch
        /// </summary>
        public async Task<List<PolicyEvaluationResult>> EvaluateEventsBatchAsync(List<SensorEvent> events)
        {
            var results = new List<PolicyEvaluationResult>();
            
            if (!_isInitialized || events == null || !events.Any())
                return results;
            
            try
            {
                // Procesar en paralelo por lotes
                var batchSize = 100;
                var batches = events.Chunk(batchSize);
                
                foreach (var batch in batches)
                {
                    var batchTasks = batch.Select(evt => Task.Run(async () =>
                    {
                        try
                        {
                            return await EvaluateEventAsync(evt);
                        }
                        catch (Exception ex)
                        {
                            _logManager.LogError($"Error en evaluación batch para evento {evt.EventId}: {ex}", ModuleId);
                            return PolicyEvaluationResult.Error($"Error: {ex.Message}");
                        }
                    }));
                    
                    var batchResults = await Task.WhenAll(batchTasks);
                    results.AddRange(batchResults);
                }
                
                _logManager.LogDebug($"Evaluación batch completada: {events.Count} eventos, {results.Count(r => r.Decision != PolicyDecision.NotApplicable)} con decisiones", ModuleId);
                
                return results;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en evaluación batch: {ex}", ModuleId);
                return results;
            }
        }
        
        /// <summary>
        /// Verifica cumplimiento de una política específica
        /// </summary>
        public async Task<PolicyComplianceCheckResult> CheckPolicyComplianceAsync(string policyId)
        {
            try
            {
                // Obtener eventos relevantes para la política
                var relevantEvents = await GetRelevantEventsForPolicyAsync(policyId, TimeSpan.FromHours(1));
                
                if (!relevantEvents.Any())
                {
                    return PolicyComplianceCheckResult.NoData(policyId, "No hay eventos relevantes para evaluación");
                }
                
                var complianceResult = new PolicyComplianceCheckResult
                {
                    PolicyId = policyId,
                    Timestamp = DateTime.UtcNow,
                    TotalEvents = relevantEvents.Count,
                    EvaluatedEvents = 0,
                    CompliantEvents = 0,
                    NonCompliantEvents = 0,
                    Violations = new List<PolicyViolationDetail>()
                };
                
                foreach (var evt in relevantEvents)
                {
                    try
                    {
                        var evaluation = await EvaluateEventAsync(evt);
                        
                        complianceResult.EvaluatedEvents++;
                        
                        if (evaluation.IsCompliant)
                        {
                            complianceResult.CompliantEvents++;
                        }
                        else
                        {
                            complianceResult.NonCompliantEvents++;
                            
                            // Registrar violaciones
                            if (evaluation.Violations != null)
                            {
                                complianceResult.Violations.AddRange(evaluation.Violations);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error evaluando evento para cumplimiento: {ex}", ModuleId);
                    }
                }
                
                // Calcular puntaje de cumplimiento
                complianceResult.ComplianceScore = complianceResult.EvaluatedEvents > 0 ?
                    (double)complianceResult.CompliantEvents / complianceResult.EvaluatedEvents * 100 : 0;
                
                complianceResult.IsCompliant = complianceResult.ComplianceScore >= 90; // Umbral del 90%
                
                return complianceResult;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error verificando cumplimiento de política {policyId}: {ex}", ModuleId);
                return PolicyComplianceCheckResult.Error(policyId, $"Error: {ex.Message}");
            }
        }
        
        #region Métodos privados
        
        private void InitializeEvaluationCache()
        {
            _evaluationCache.Clear();
            _logManager.LogInfo("Caché de evaluación inicializada", ModuleId);
        }
        
        private void SetupCacheCleanup()
        {
            // Programar limpieza periódica de caché
            Task.Run(async () =>
            {
                while (_isRunning)
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMinutes(CACHE_TTL_MINUTES));
                        CleanupExpiredCache();
                    }
                    catch (Exception ex)
                    {
                        _logManager.LogError($"Error en limpieza de caché: {ex}", ModuleId);
                    }
                }
            });
        }
        
        private async Task VerifyPolicyManagerIntegrationAsync()
        {
            try
            {
                var policyCount = await _policyManager.GetPolicyReportAsync(TimeSpan.FromMinutes(5));
                if (policyCount == null)
                {
                    throw new Exception("No se pudo conectar con PolicyManager");
                }
                
                _logManager.LogInfo("Integración con PolicyManager verificada", ModuleId);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error en integración con PolicyManager: {ex.Message}");
            }
        }
        
        private string GenerateCacheKey(SensorEvent sensorEvent)
        {
            // Generar clave basada en propiedades del evento
            var keyParts = new[]
            {
                sensorEvent.EventType.ToString(),
                sensorEvent.SensorType.ToString(),
                sensorEvent.Data?.ProcessName,
                sensorEvent.Data?.FilePath,
                sensorEvent.Data?.RemoteAddress,
                sensorEvent.Data?.RegistryPath
            };
            
            return string.Join("|", keyParts.Where(p => !string.IsNullOrEmpty(p)));
        }
        
        private bool IsCacheExpired(PolicyEvaluationCache cacheEntry)
        {
            return DateTime.UtcNow - cacheEntry.CachedAt > TimeSpan.FromMinutes(CACHE_TTL_MINUTES);
        }
        
        private void CacheEvaluationResult(string cacheKey, PolicyEvaluationResult result, SensorEvent sensorEvent)
        {
            try
            {
                var cacheEntry = new PolicyEvaluationCache
                {
                    Result = result,
                    CachedAt = DateTime.UtcNow,
                    EventType = sensorEvent.EventType,
                    SensorType = sensorEvent.SensorType
                };
                
                _evaluationCache[cacheKey] = cacheEntry;
                
                // Limitar tamaño de caché
                if (_evaluationCache.Count > CACHE_SIZE)
                {
                    var oldest = _evaluationCache.OrderBy(kv => kv.Value.CachedAt).First();
                    _evaluationCache.TryRemove(oldest.Key, out _);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cacheando resultado: {ex}", ModuleId);
            }
        }
        
        private void CleanupExpiredCache()
        {
            try
            {
                var expiredKeys = _evaluationCache
                    .Where(kv => IsCacheExpired(kv.Value))
                    .Select(kv => kv.Key)
                    .ToList();
                
                foreach (var key in expiredKeys)
                {
                    _evaluationCache.TryRemove(key, out _);
                }
                
                if (expiredKeys.Count > 0)
                {
                    _logManager.LogDebug($"Limpieza de caché: {expiredKeys.Count} entradas expiradas eliminadas", ModuleId);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error en limpieza de caché: {ex}", ModuleId);
            }
        }
        
        private async Task<PolicyEvaluationResult> EvaluateAgainstPoliciesAsync(
            SensorEvent sensorEvent, 
            List<SecurityPolicy> policies)
        {
            var result = new PolicyEvaluationResult
            {
                EventId = sensorEvent.EventId,
                Timestamp = DateTime.UtcNow,
                TotalPoliciesEvaluated = policies.Count,
                PolicyEvaluations = new List<SinglePolicyEvaluationResult>(),
                Actions = new List<PolicyAction>(),
                Violations = new List<PolicyViolationDetail>()
            };
            
            foreach (var policy in policies)
            {
                try
                {
                    var policyEvaluation = await EvaluateAgainstPolicyAsync(sensorEvent, policy);
                    result.PolicyEvaluations.Add(policyEvaluation);
                    
                    // Acumular acciones
                    if (policyEvaluation.Actions != null)
                    {
                        result.Actions.AddRange(policyEvaluation.Actions);
                    }
                    
                    // Acumular violaciones
                    if (policyEvaluation.Violations != null)
                    {
                        result.Violations.AddRange(policyEvaluation.Violations);
                    }
                    
                    // Determinar si hubo bloqueo o cuarentena
                    if (policyEvaluation.Actions?.Any(a => a.ActionType == PolicyActionType.Block) == true)
                    {
                        result.Blocked = true;
                    }
                    
                    if (policyEvaluation.Actions?.Any(a => a.ActionType == PolicyActionType.Quarantine) == true)
                    {
                        result.Quarantined = true;
                    }
                    
                    if (policyEvaluation.Actions?.Any(a => a.ActionType == PolicyActionType.Alert) == true)
                    {
                        result.Alerted = true;
                    }
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error evaluando política {policy.PolicyId}: {ex}", ModuleId);
                }
            }
            
            // Determinar decisión global
            result.Decision = DetermineOverallDecision(result);
            result.IsCompliant = result.Decision == PolicyDecision.Allow || 
                                 result.Decision == PolicyDecision.Monitor;
            
            // Registrar evaluación
            await LogEvaluationResultAsync(result);
            
            return result;
        }
        
        private async Task<bool> PolicyAppliesToEventAsync(SecurityPolicy policy, SensorEvent sensorEvent)
        {
            // Verificar ámbito
            if (policy.Scope == PolicyScope.Global)
                return true;
            
            // Verificar tipos de eventos aplicables
            if (policy.Rules != null)
            {
                foreach (var rule in policy.Rules)
                {
                    if (RuleAppliesToEvent(rule, sensorEvent))
                        return true;
                }
            }
            
            return false;
        }
        
        private bool RuleAppliesToEvent(PolicyRule rule, SensorEvent sensorEvent)
        {
            // Determinar si la regla aplica al tipo de evento
            switch (rule.RuleType)
            {
                case PolicyRuleType.ProcessRestriction:
                    return sensorEvent.SensorType == SensorType.Process;
                    
                case PolicyRuleType.FileAccessControl:
                    return sensorEvent.SensorType == SensorType.FileSystem;
                    
                case PolicyRuleType.NetworkRestriction:
                    return sensorEvent.SensorType == SensorType.Network;
                    
                case PolicyRuleType.RegistryRestriction:
                    return sensorEvent.SensorType == SensorType.Registry;
                    
                case PolicyRuleType.MemoryProtection:
                    return sensorEvent.SensorType == SensorType.Process;
                    
                default:
                    return false;
            }
        }
        
        private async Task<bool> EvaluatePolicyConditionsAsync(SecurityPolicy policy, SensorEvent sensorEvent)
        {
            if (policy.Conditions == null || !policy.Conditions.Any())
                return true;
            
            return await EvaluateConditionsRecursiveAsync(policy.Conditions, sensorEvent);
        }
        
        private async Task<bool> EvaluateConditionsRecursiveAsync(List<PolicyCondition> conditions, SensorEvent sensorEvent)
        {
            bool result = true;
            
            foreach (var condition in conditions)
            {
                var conditionResult = await EvaluateSingleConditionAsync(condition, sensorEvent);
                
                if (condition.LogicalOperator == ConditionLogicalOperator.And)
                {
                    result = result && conditionResult;
                }
                else if (condition.LogicalOperator == ConditionLogicalOperator.Or)
                {
                    result = result || conditionResult;
                }
                else if (condition.LogicalOperator == ConditionLogicalOperator.Not)
                {
                    result = !conditionResult;
                }
                
                // Evaluar subcondiciones si existen
                if (condition.SubConditions != null && condition.SubConditions.Any())
                {
                    var subResult = await EvaluateConditionsRecursiveAsync(condition.SubConditions, sensorEvent);
                    
                    if (condition.LogicalOperator == ConditionLogicalOperator.And)
                    {
                        result = result && subResult;
                    }
                    else if (condition.LogicalOperator == ConditionLogicalOperator.Or)
                    {
                        result = result || subResult;
                    }
                }
            }
            
            return result;
        }
        
        private async Task<bool> EvaluateSingleConditionAsync(PolicyCondition condition, SensorEvent sensorEvent)
        {
            try
            {
                // Obtener valor de la propiedad del evento
                var propertyValue = GetEventPropertyValue(sensorEvent, condition.Property);
                
                // Comparar según operador
                switch (condition.Operator)
                {
                    case ConditionOperator.Equals:
                        return Equals(propertyValue, condition.Value);
                        
                    case ConditionOperator.NotEquals:
                        return !Equals(propertyValue, condition.Value);
                        
                    case ConditionOperator.Contains:
                        return propertyValue?.ToString()?.Contains(condition.Value?.ToString() ?? "") == true;
                        
                    case ConditionOperator.NotContains:
                        return propertyValue?.ToString()?.Contains(condition.Value?.ToString() ?? "") == false;
                        
                    case ConditionOperator.StartsWith:
                        return propertyValue?.ToString()?.StartsWith(condition.Value?.ToString() ?? "") == true;
                        
                    case ConditionOperator.EndsWith:
                        return propertyValue?.ToString()?.EndsWith(condition.Value?.ToString() ?? "") == true;
                        
                    case ConditionOperator.GreaterThan:
                        return CompareValues(propertyValue, condition.Value) > 0;
                        
                    case ConditionOperator.LessThan:
                        return CompareValues(propertyValue, condition.Value) < 0;
                        
                    case ConditionOperator.GreaterOrEqual:
                        return CompareValues(propertyValue, condition.Value) >= 0;
                        
                    case ConditionOperator.LessOrEqual:
                        return CompareValues(propertyValue, condition.Value) <= 0;
                        
                    case ConditionOperator.In:
                        var valueList = condition.Value as IEnumerable<object>;
                        return valueList?.Contains(propertyValue) == true;
                        
                    case ConditionOperator.NotIn:
                        var valueList2 = condition.Value as IEnumerable<object>;
                        return valueList2?.Contains(propertyValue) == false;
                        
                    case ConditionOperator.Matches:
                        if (propertyValue is string strValue && condition.Value is string pattern)
                        {
                            return Regex.IsMatch(strValue, pattern);
                        }
                        return false;
                        
                    case ConditionOperator.NotMatches:
                        if (propertyValue is string strValue2 && condition.Value is string pattern2)
                        {
                            return !Regex.IsMatch(strValue2, pattern2);
                        }
                        return false;
                        
                    default:
                        return false;
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error evaluando condición: {ex}", ModuleId);
                return false;
            }
        }
        
        private object GetEventPropertyValue(SensorEvent sensorEvent, string propertyPath)
        {
            // Implementar obtención de valor de propiedad anidada
            // Por simplicidad, aquí un ejemplo básico
            switch (propertyPath.ToLowerInvariant())
            {
                case "eventtype":
                    return sensorEvent.EventType.ToString();
                    
                case "sensortype":
                    return sensorEvent.SensorType.ToString();
                    
                case "processname":
                    return sensorEvent.Data?.ProcessName;
                    
                case "filepath":
                    return sensorEvent.Data?.FilePath;
                    
                case "remoteaddress":
                    return sensorEvent.Data?.RemoteAddress;
                    
                case "registrypath":
                    return sensorEvent.Data?.RegistryPath;
                    
                case "username":
                    return sensorEvent.Data?.UserName;
                    
                case "operationtype":
                    return sensorEvent.Data?.OperationType;
                    
                default:
                    return null;
            }
        }
        
        private int CompareValues(object value1, object value2)
        {
            if (value1 == null || value2 == null)
                return 0;
            
            if (value1 is IComparable comparable1 && value2 is IComparable comparable2)
            {
                try
                {
                    return comparable1.CompareTo(comparable2);
                }
                catch
                {
                    return 0;
                }
            }
            
            return 0;
        }
        
        private async Task<List<PolicyRuleEvaluationResult>> EvaluatePolicyRulesAsync(
            SecurityPolicy policy, 
            SensorEvent sensorEvent)
        {
            var ruleResults = new List<PolicyRuleEvaluationResult>();
            
            if (policy.Rules == null || !policy.Rules.Any())
                return ruleResults;
            
            foreach (var rule in policy.Rules)
            {
                try
                {
                    // Verificar si la regla aplica al evento
                    if (!RuleAppliesToEvent(rule, sensorEvent))
                    {
                        ruleResults.Add(new PolicyRuleEvaluationResult
                        {
                            RuleId = rule.RuleId,
                            RuleName = rule.Name,
                            IsApplicable = false,
                            Decision = PolicyDecision.NotApplicable,
                            Message = "Regla no aplicable a este evento"
                        });
                        continue;
                    }
                    
                    // Evaluar condiciones específicas de la regla
                    var ruleConditionsMet = await EvaluateRuleConditionsAsync(rule, sensorEvent);
                    if (!ruleConditionsMet)
                    {
                        ruleResults.Add(new PolicyRuleEvaluationResult
                        {
                            RuleId = rule.RuleId,
                            RuleName = rule.Name,
                            IsApplicable = true,
                            Decision = PolicyDecision.ConditionsNotMet,
                            Message = "Condiciones de regla no cumplidas"
                        });
                        continue;
                    }
                    
                    // Evaluar lógica de la regla
                    var ruleEvaluation = await EvaluateRuleLogicAsync(rule, sensorEvent);
                    
                    ruleResults.Add(ruleEvaluation);
                }
                catch (Exception ex)
                {
                    _logManager.LogError($"Error evaluando regla {rule.RuleId}: {ex}", ModuleId);
                    
                    ruleResults.Add(new PolicyRuleEvaluationResult
                    {
                        RuleId = rule.RuleId,
                        RuleName = rule.Name,
                        IsApplicable = true,
                        Decision = PolicyDecision.Error,
                        Message = $"Error: {ex.Message}",
                        Error = ex.Message
                    });
                }
            }
            
            return ruleResults;
        }
        
        private async Task<bool> EvaluateRuleConditionsAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            // Evaluar condiciones específicas de la regla
            // Por ahora, siempre true (implementación simplificada)
            return true;
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateRuleLogicAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true,
                Timestamp = DateTime.UtcNow
            };
            
            try
            {
                // Implementar lógica específica según tipo de regla
                switch (rule.RuleType)
                {
                    case PolicyRuleType.ProcessRestriction:
                        result = await EvaluateProcessRestrictionRuleAsync(rule, sensorEvent);
                        break;
                        
                    case PolicyRuleType.FileAccessControl:
                        result = await EvaluateFileAccessControlRuleAsync(rule, sensorEvent);
                        break;
                        
                    case PolicyRuleType.NetworkRestriction:
                        result = await EvaluateNetworkRestrictionRuleAsync(rule, sensorEvent);
                        break;
                        
                    case PolicyRuleType.RegistryRestriction:
                        result = await EvaluateRegistryRestrictionRuleAsync(rule, sensorEvent);
                        break;
                        
                    case PolicyRuleType.MemoryProtection:
                        result = await EvaluateMemoryProtectionRuleAsync(rule, sensorEvent);
                        break;
                        
                    default:
                        result.Decision = PolicyDecision.Error;
                        result.Message = $"Tipo de regla no soportado: {rule.RuleType}";
                        break;
                }
                
                // Añadir acciones si la regla no es compliant
                if (result.Decision == PolicyDecision.Block || 
                    result.Decision == PolicyDecision.Quarantine ||
                    result.Decision == PolicyDecision.Alert)
                {
                    result.Actions = rule.Actions?.ToList() ?? new List<PolicyAction>();
                    
                    // Añadir violaciones
                    if (result.Decision != PolicyDecision.Allow)
                    {
                        result.Violations.Add(new PolicyViolationDetail
                        {
                            RuleId = rule.RuleId,
                            RuleName = rule.Name,
                            Description = rule.Description,
                            Severity = rule.Severity,
                            DetectedAt = DateTime.UtcNow,
                            Details = new Dictionary<string, object>
                            {
                                { "EventType", sensorEvent.EventType.ToString() },
                                { "SensorType", sensorEvent.SensorType.ToString() },
                                { "Decision", result.Decision.ToString() }
                            }
                        });
                    }
                }
                
                return result;
            }
            catch (Exception ex)
            {
                result.Decision = PolicyDecision.Error;
                result.Message = $"Error en evaluación de regla: {ex.Message}";
                result.Error = ex.Message;
                return result;
            }
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateProcessRestrictionRuleAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true
            };
            
            // Verificar si el proceso está restringido
            var processName = sensorEvent.Data?.ProcessName;
            var imagePath = sensorEvent.Data?.ImagePath;
            var commandLine = sensorEvent.Data?.CommandLine;
            
            if (string.IsNullOrEmpty(processName))
            {
                result.Decision = PolicyDecision.Allow;
                result.Message = "No hay información de proceso para evaluar";
                return result;
            }
            
            // Verificar en lista de procesos restringidos
            if (rule.Parameters.TryGetValue("RestrictedProcesses", out var restrictedObj) &&
                restrictedObj is List<string> restrictedProcesses)
            {
                if (restrictedProcesses.Any(rp => 
                    processName.Contains(rp, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(imagePath) && imagePath.Contains(rp, StringComparison.OrdinalIgnoreCase)) ||
                    (!string.IsNullOrEmpty(commandLine) && commandLine.Contains(rp, StringComparison.OrdinalIgnoreCase))))
                {
                    result.Decision = PolicyDecision.Block;
                    result.Message = $"Proceso restringido detectado: {processName}";
                    return result;
                }
            }
            
            result.Decision = PolicyDecision.Allow;
            result.Message = "Proceso permitido";
            return result;
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateFileAccessControlRuleAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true
            };
            
            var filePath = sensorEvent.Data?.FilePath;
            var operationType = sensorEvent.Data?.OperationType;
            
            if (string.IsNullOrEmpty(filePath))
            {
                result.Decision = PolicyDecision.Allow;
                result.Message = "No hay información de archivo para evaluar";
                return result;
            }
            
            // Verificar operaciones en ubicaciones protegidas
            if (rule.Parameters.TryGetValue("ProtectedPaths", out var protectedObj) &&
                protectedObj is List<string> protectedPaths)
            {
                if (protectedPaths.Any(pp => filePath.StartsWith(pp, StringComparison.OrdinalIgnoreCase)))
                {
                    // Verificar si la operación está permitida
                    if (rule.Parameters.TryGetValue("AllowedOperations", out var allowedOpsObj) &&
                        allowedOpsObj is List<string> allowedOperations)
                    {
                        if (!allowedOperations.Contains(operationType ?? "", StringComparer.OrdinalIgnoreCase))
                        {
                            result.Decision = PolicyDecision.Block;
                            result.Message = $"Operación no permitida en ubicación protegida: {operationType} en {filePath}";
                            return result;
                        }
                    }
                }
            }
            
            result.Decision = PolicyDecision.Allow;
            result.Message = "Acceso a archivo permitido";
            return result;
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateNetworkRestrictionRuleAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true
            };
            
            var remoteAddress = sensorEvent.Data?.RemoteAddress;
            var remotePort = sensorEvent.Data?.RemotePort;
            var dnsName = sensorEvent.Data?.DnsName;
            
            if (string.IsNullOrEmpty(remoteAddress) && string.IsNullOrEmpty(dnsName))
            {
                result.Decision = PolicyDecision.Allow;
                result.Message = "No hay información de red para evaluar";
                return result;
            }
            
            // Verificar direcciones/bloques IP restringidos
            if (rule.Parameters.TryGetValue("RestrictedIPs", out var restrictedIPsObj) &&
                restrictedIPsObj is List<string> restrictedIPs)
            {
                if (!string.IsNullOrEmpty(remoteAddress) && 
                    restrictedIPs.Any(ip => remoteAddress.StartsWith(ip)))
                {
                    result.Decision = PolicyDecision.Block;
                    result.Message = $"Conexión a IP restringida: {remoteAddress}";
                    return result;
                }
            }
            
            // Verificar dominios restringidos
            if (rule.Parameters.TryGetValue("RestrictedDomains", out var restrictedDomainsObj) &&
                restrictedDomainsObj is List<string> restrictedDomains)
            {
                if (!string.IsNullOrEmpty(dnsName) && 
                    restrictedDomains.Any(domain => dnsName.EndsWith(domain, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Decision = PolicyDecision.Block;
                    result.Message = $"Conexión a dominio restringido: {dnsName}";
                    return result;
                }
            }
            
            result.Decision = PolicyDecision.Allow;
            result.Message = "Conexión de red permitida";
            return result;
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateRegistryRestrictionRuleAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true
            };
            
            var registryPath = sensorEvent.Data?.RegistryPath;
            var operationType = sensorEvent.Data?.OperationType;
            
            if (string.IsNullOrEmpty(registryPath))
            {
                result.Decision = PolicyDecision.Allow;
                result.Message = "No hay información de registro para evaluar";
                return result;
            }
            
            // Verificar claves de registro protegidas
            if (rule.Parameters.TryGetValue("ProtectedKeys", out var protectedKeysObj) &&
                protectedKeysObj is List<string> protectedKeys)
            {
                if (protectedKeys.Any(pk => registryPath.StartsWith(pk, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Decision = PolicyDecision.Block;
                    result.Message = $"Acceso a clave de registro protegida: {registryPath}";
                    return result;
                }
            }
            
            // Verificar claves de auto-inicio
            if (registryPath.Contains(@"Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase))
            {
                if (operationType == "SetValue")
                {
                    result.Decision = PolicyDecision.Alert;
                    result.Message = $"Modificación de clave de auto-inicio detectada: {registryPath}";
                    return result;
                }
            }
            
            result.Decision = PolicyDecision.Allow;
            result.Message = "Acceso a registro permitido";
            return result;
        }
        
        private async Task<PolicyRuleEvaluationResult> EvaluateMemoryProtectionRuleAsync(PolicyRule rule, SensorEvent sensorEvent)
        {
            // Implementar evaluación de protección de memoria
            var result = new PolicyRuleEvaluationResult
            {
                RuleId = rule.RuleId,
                RuleName = rule.Name,
                IsApplicable = true,
                Decision = PolicyDecision.Allow,
                Message = "Evaluación de protección de memoria (implementación simplificada)"
            };
            
            return result;
        }
        
        private PolicyDecision DeterminePolicyDecision(List<PolicyRuleEvaluationResult> ruleResults)
        {
            if (!ruleResults.Any())
                return PolicyDecision.NotApplicable;
            
            // Prioridad de decisiones: Block > Quarantine > Alert > Deny > Allow > Monitor > NotApplicable
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Block))
                return PolicyDecision.Block;
            
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Quarantine))
                return PolicyDecision.Quarantine;
            
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Alert))
                return PolicyDecision.Alert;
            
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Deny))
                return PolicyDecision.Deny;
            
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Allow))
                return PolicyDecision.Allow;
            
            if (ruleResults.Any(r => r.Decision == PolicyDecision.Monitor))
                return PolicyDecision.Monitor;
            
            return PolicyDecision.NotApplicable;
        }
        
        private PolicyDecision DetermineOverallDecision(PolicyEvaluationResult evaluationResult)
        {
            // Tomar la decisión más restrictiva de todas las evaluaciones
            var allDecisions = evaluationResult.PolicyEvaluations
                .Select(e => e.Decision)
                .ToList();
            
            return DeterminePolicyDecision(allDecisions.Select(d => new PolicyRuleEvaluationResult { Decision = d }).ToList());
        }
        
        private async Task RecordEvaluationMetricsAsync(SinglePolicyEvaluationResult result)
        {
            try
            {
                // Registrar métricas para análisis de rendimiento
                // Implementación simplificada
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error registrando métricas: {ex}", ModuleId);
            }
        }
        
        private async Task LogEvaluationResultAsync(PolicyEvaluationResult result)
        {
            try
            {
                // Registrar resultado de evaluación
                // Implementación simplificada
                await Task.CompletedTask;
                
                _logManager.LogDebug($"Evaluación completada para evento {result.EventId}: {result.Decision}", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error registrando evaluación: {ex}", ModuleId);
            }
        }
        
        private async Task<List<SensorEvent>> GetRelevantEventsForPolicyAsync(string policyId, TimeSpan timeWindow)
        {
            // Obtener eventos relevantes para la política
            // Implementación simplificada - en producción obtener desde base de datos
            return new List<SensorEvent>();
        }
        
        #endregion
        
        #region Métodos públicos adicionales
        
        public async Task<PolicyEvaluationStats> GetEvaluationStatsAsync(TimeSpan? period = null)
        {
            period ??= TimeSpan.FromHours(1);
            
            try
            {
                var stats = new PolicyEvaluationStats
                {
                    Timestamp = DateTime.UtcNow,
                    Period = period.Value,
                    CacheSize = _evaluationCache.Count,
                    CacheHitRate = CalculateCacheHitRate(),
                    TotalEvaluations = 0,
                    AverageEvaluationTimeMs = 0,
                    DecisionDistribution = new Dictionary<PolicyDecision, int>(),
                    PolicyPerformance = new List<PolicyPerformanceMetric>()
                };
                
                // Inicializar distribución de decisiones
                foreach (PolicyDecision decision in Enum.GetValues(typeof(PolicyDecision)))
                {
                    stats.DecisionDistribution[decision] = 0;
                }
                
                return stats;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo estadísticas: {ex}", ModuleId);
                return PolicyEvaluationStats.Error($"Error: {ex.Message}");
            }
        }
        
        private double CalculateCacheHitRate()
        {
            // Implementar cálculo de tasa de aciertos de caché
            // Por ahora, valor simulado
            return 0.75;
        }
        
        public async Task<HealthCheckResult> CheckHealthAsync()
        {
            try
            {
                var issues = new List<string>();
                
                if (!_isInitialized)
                    issues.Add("No inicializado");
                
                if (!_isRunning)
                    issues.Add("No en ejecución");
                
                if (_evaluationCache.Count == 0 && _isRunning)
                    issues.Add("Caché vacía");
                
                // Verificar integración con PolicyManager
                try
                {
                    var policyReport = await _policyManager.GetPolicyReportAsync(TimeSpan.FromMinutes(5));
                    if (policyReport == null)
                    {
                        issues.Add("No se pudo obtener reporte de PolicyManager");
                    }
                }
                catch (Exception ex)
                {
                    issues.Add($"Error en integración con PolicyManager: {ex.Message}");
                }
                
                if (issues.Count == 0)
                {
                    return HealthCheckResult.Healthy("PolicyEvaluator funcionando correctamente");
                }
                
                return HealthCheckResult.Degraded(
                    string.Join(", ", issues),
                    new Dictionary<string, object>
                    {
                        { "IsInitialized", _isInitialized },
                        { "IsRunning", _isRunning },
                        { "CacheSize", _evaluationCache.Count },
                        { "CacheHitRate", CalculateCacheHitRate() }
                    });
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy(
                    $"Error en health check: {ex.Message}",
                    new Dictionary<string, object>
                    {
                        { "Exception", ex.ToString() }
                    });
            }
        }
        
        public async Task ClearCacheAsync()
        {
            try
            {
                _evaluationCache.Clear();
                _logManager.LogInfo("Caché de evaluación limpiada", ModuleId);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error limpiando caché: {ex}", ModuleId);
            }
        }
        
        #region Implementación IAgentModule
        
        public async Task<ModuleOperationResult> StartAsync()
        {
            if (!_isInitialized)
            {
                var initResult = await InitializeAsync();
                if (!initResult.Success)
                    return initResult;
            }
            
            _isRunning = true;
            _logManager.LogInfo("PolicyEvaluator iniciado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> StopAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("PolicyEvaluator detenido", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> PauseAsync()
        {
            _isRunning = false;
            _logManager.LogInfo("PolicyEvaluator pausado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        public async Task<ModuleOperationResult> ResumeAsync()
        {
            _isRunning = true;
            _logManager.LogInfo("PolicyEvaluator reanudado", ModuleId);
            return ModuleOperationResult.SuccessResult();
        }
        
        #endregion
        
        #endregion
    }
    
    #region Clases y estructuras de datos
    
    public class PolicyEvaluationCache
    {
        public PolicyEvaluationResult Result { get; set; }
        public DateTime CachedAt { get; set; }
        public EventType EventType { get; set; }
        public SensorType SensorType { get; set; }
    }
    
    public class PolicyEvaluationResult
    {
        public string EventId { get; set; }
        public DateTime Timestamp { get; set; }
        public int TotalPoliciesEvaluated { get; set; }
        public List<SinglePolicyEvaluationResult> PolicyEvaluations { get; set; }
        public PolicyDecision Decision { get; set; }
        public bool IsCompliant { get; set; }
        public List<PolicyAction> Actions { get; set; }
        public List<PolicyViolationDetail> Violations { get; set; }
        public bool Blocked { get; set; }
        public bool Quarantined { get; set; }
        public bool Alerted { get; set; }
        public string ErrorMessage { get; set; }
        
        public PolicyEvaluationResult()
        {
            PolicyEvaluations = new List<SinglePolicyEvaluationResult>();
            Actions = new List<PolicyAction>();
            Violations = new List<PolicyViolationDetail>();
        }
        
        public static PolicyEvaluationResult NoPolicyApplicable(string eventId)
        {
            return new PolicyEvaluationResult
            {
                EventId = eventId,
                Timestamp = DateTime.UtcNow,
                Decision = PolicyDecision.NotApplicable,
                IsCompliant = true,
                Message = "No hay políticas aplicables a este evento"
            };
        }
        
        public static PolicyEvaluationResult Error(string errorMessage)
        {
            return new PolicyEvaluationResult
            {
                Timestamp = DateTime.UtcNow,
                Decision = PolicyDecision.Error,
                IsCompliant = false,
                ErrorMessage = errorMessage
            };
        }
    }
    
    public class SinglePolicyEvaluationResult
    {
        public string PolicyId { get; set; }
        public string PolicyName { get; set; }
        public string EventId { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsApplicable { get; set; }
        public PolicyDecision Decision { get; set; }
        public string Message { get; set; }
        public List<PolicyRuleEvaluationResult> ApplicableRules { get; set; }
        public List<PolicyAction> Actions { get; set; }
        public List<PolicyViolationDetail> Violations { get; set; }
        public string Error { get; set; }
        
        public SinglePolicyEvaluationResult()
        {
            ApplicableRules = new List<PolicyRuleEvaluationResult>();
            Actions = new List<PolicyAction>();
            Violations = new List<PolicyViolationDetail>();
        }
        
        public static SinglePolicyEvaluationResult Error(string policyId, string errorMessage)
        {
            return new SinglePolicyEvaluationResult
            {
                PolicyId = policyId,
                Timestamp = DateTime.UtcNow,
                Decision = PolicyDecision.Error,
                Message = errorMessage,
                Error = errorMessage
            };
        }
    }
    
    public class PolicyRuleEvaluationResult
    {
        public string RuleId { get; set; }
        public string RuleName { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsApplicable { get; set; }
        public PolicyDecision Decision { get; set; }
        public string Message { get; set; }
        public List<PolicyAction> Actions { get; set; }
        public List<PolicyViolationDetail> Violations { get; set; }
        public string Error { get; set; }
        
        public PolicyRuleEvaluationResult()
        {
            Actions = new List<PolicyAction>();
            Violations = new List<PolicyViolationDetail>();
        }
    }
    
    public class PolicyViolationDetail
    {
        public string ViolationId { get; set; }
        public string RuleId { get; set; }
        public string RuleName { get; set; }
        public string Description { get; set; }
        public ThreatSeverity Severity { get; set; }
        public DateTime DetectedAt { get; set; }
        public Dictionary<string, object> Details { get; set; }
        
        public PolicyViolationDetail()
        {
            Details = new Dictionary<string, object>();
        }
    }
    
    public class PolicyComplianceCheckResult
    {
        public string PolicyId { get; set; }
        public DateTime Timestamp { get; set; }
        public int TotalEvents { get; set; }
        public int EvaluatedEvents { get; set; }
        public int CompliantEvents { get; set; }
        public int NonCompliantEvents { get; set; }
        public double ComplianceScore { get; set; }
        public bool IsCompliant { get; set; }
        public List<PolicyViolationDetail> Violations { get; set; }
        public string Message { get; set; }
        public string Error { get; set; }
        
        public PolicyComplianceCheckResult()
        {
            Violations = new List<PolicyViolationDetail>();
        }
        
        public static PolicyComplianceCheckResult NoData(string policyId, string message)
        {
            return new PolicyComplianceCheckResult
            {
                PolicyId = policyId,
                Timestamp = DateTime.UtcNow,
                Message = message
            };
        }
        
        public static PolicyComplianceCheckResult Error(string policyId, string errorMessage)
        {
            return new PolicyComplianceCheckResult
            {
                PolicyId = policyId,
                Timestamp = DateTime.UtcNow,
                Error = errorMessage
            };
        }
    }
    
    public class PolicyEvaluationStats
    {
        public DateTime Timestamp { get; set; }
        public TimeSpan Period { get; set; }
        public int CacheSize { get; set; }
        public double CacheHitRate { get; set; }
        public int TotalEvaluations { get; set; }
        public double AverageEvaluationTimeMs { get; set; }
        public Dictionary<PolicyDecision, int> DecisionDistribution { get; set; }
        public List<PolicyPerformanceMetric> PolicyPerformance { get; set; }
        public string Error { get; set; }
        
        public PolicyEvaluationStats()
        {
            DecisionDistribution = new Dictionary<PolicyDecision, int>();
            PolicyPerformance = new List<PolicyPerformanceMetric>();
        }
        
        public static PolicyEvaluationStats Error(string errorMessage)
        {
            return new PolicyEvaluationStats
            {
                Error = errorMessage,
                Timestamp = DateTime.UtcNow
            };
        }
    }
    
    public class PolicyPerformanceMetric
    {
        public string PolicyId { get; set; }
        public string PolicyName { get; set; }
        public int EvaluationCount { get; set; }
        public double AverageEvaluationTimeMs { get; set; }
        public int BlockCount { get; set; }
        public int AlertCount { get; set; }
        public double ComplianceRate { get; set; }
    }
    
    public enum PolicyDecision
    {
        Allow,
        Deny,
        Block,
        Quarantine,
        Alert,
        Monitor,
        NotApplicable,
        ConditionsNotMet,
        Error
    }
    
    #endregion
}