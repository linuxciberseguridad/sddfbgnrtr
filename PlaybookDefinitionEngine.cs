using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.SOAR
{
    /// <summary>
    /// Motor para definición, validación y gestión de playbooks de automatización SOAR
    /// Permite crear flujos de trabajo automatizados para respuesta a incidentes
    /// </summary>
    public sealed class PlaybookDefinitionEngine : IPlaybookEngine
    {
        private readonly ILogger<PlaybookDefinitionEngine> _logger;
        private readonly IPlaybookRepository _repository;
        private readonly IActionOrchestrator _orchestrator;
        private readonly IApprovalEngine _approvalEngine;
        
        private readonly ConcurrentDictionary<string, PlaybookDefinition> _playbooks;
        private readonly ConcurrentDictionary<string, PlaybookExecution> _executions;
        private readonly ConcurrentDictionary<string, PlaybookTemplate> _templates;
        
        private readonly PlaybookValidator _validator;
        private readonly PlaybookCompiler _compiler;
        private readonly PlaybookScheduler _scheduler;
        
        private bool _isInitialized;
        private readonly SemaphoreSlim _initLock = new SemaphoreSlim(1, 1);
        
        public PlaybookDefinitionEngine(
            ILogger<PlaybookDefinitionEngine> logger,
            IPlaybookRepository repository,
            IActionOrchestrator orchestrator,
            IApprovalEngine approvalEngine)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _repository = repository ?? throw new ArgumentNullException(nameof(repository));
            _orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
            _approvalEngine = approvalEngine ?? throw new ArgumentNullException(nameof(approvalEngine));
            
            _playbooks = new ConcurrentDictionary<string, PlaybookDefinition>();
            _executions = new ConcurrentDictionary<string, PlaybookExecution>();
            _templates = new ConcurrentDictionary<string, PlaybookTemplate>();
            
            _validator = new PlaybookValidator();
            _compiler = new PlaybookCompiler();
            _scheduler = new PlaybookScheduler();
            
            _isInitialized = false;
        }
        
        /// <summary>
        /// Inicializa el motor de playbooks
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await _initLock.WaitAsync(cancellationToken);
            
            try
            {
                if (_isInitialized)
                    return;
                
                _logger.LogInformation("Inicializando PlaybookDefinitionEngine...");
                
                // Cargar playbooks desde el repositorio
                await LoadPlaybooksFromRepositoryAsync(cancellationToken);
                
                // Cargar templates predefinidos
                await LoadPredefinedTemplatesAsync(cancellationToken);
                
                // Inicializar componentes internos
                await _validator.InitializeAsync(cancellationToken);
                await _compiler.InitializeAsync(cancellationToken);
                await _scheduler.InitializeAsync(cancellationToken);
                
                // Suscribirse a eventos
                SubscribeToEvents();
                
                _isInitialized = true;
                _logger.LogInformation($"PlaybookDefinitionEngine inicializado: {_playbooks.Count} playbooks, {_templates.Count} templates");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al inicializar PlaybookDefinitionEngine");
                throw;
            }
            finally
            {
                _initLock.Release();
            }
        }
        
        /// <summary>
        /// Crea un nuevo playbook
        /// </summary>
        public async Task<PlaybookDefinition> CreatePlaybookAsync(
            PlaybookCreateRequest request, 
            string createdBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                _logger.LogInformation("Creando nuevo playbook: {PlaybookName}", request.Name);
                
                // Validar request
                var validationResult = await _validator.ValidateCreateRequestAsync(request, cancellationToken);
                if (!validationResult.IsValid)
                {
                    throw new PlaybookValidationException(
                        $"Solicitud de creación inválida: {string.Join(", ", validationResult.Errors)}");
                }
                
                // Crear definición del playbook
                var playbook = new PlaybookDefinition
                {
                    PlaybookId = GeneratePlaybookId(),
                    Name = request.Name,
                    Description = request.Description,
                    Version = "1.0.0",
                    Category = request.Category,
                    Priority = request.Priority,
                    TriggerConditions = request.TriggerConditions ?? new List<TriggerCondition>(),
                    Steps = request.Steps ?? new List<PlaybookStep>(),
                    Outputs = request.Outputs ?? new List<PlaybookOutput>(),
                    Metadata = request.Metadata ?? new Dictionary<string, object>(),
                    
                    CreatedBy = createdBy,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedBy = createdBy,
                    UpdatedAt = DateTime.UtcNow,
                    
                    IsActive = true,
                    IsTemplate = request.IsTemplate,
                    RequiresApproval = request.RequiresApproval,
                    ApprovalWorkflow = request.ApprovalWorkflow,
                    
                    ExecutionTimeout = request.ExecutionTimeout ?? TimeSpan.FromHours(1),
                    MaxRetries = request.MaxRetries ?? 3,
                    RetryDelay = request.RetryDelay ?? TimeSpan.FromSeconds(30)
                };
                
                // Compilar playbook
                var compilationResult = await _compiler.CompileAsync(playbook, cancellationToken);
                if (!compilationResult.Success)
                {
                    throw new PlaybookCompilationException(
                        $"Error al compilar playbook: {compilationResult.ErrorMessage}");
                }
                
                playbook.CompiledSteps = compilationResult.CompiledSteps;
                playbook.ValidationErrors = compilationResult.ValidationErrors;
                playbook.IsValid = compilationResult.IsValid;
                
                // Guardar en repositorio
                await _repository.SavePlaybookAsync(playbook, cancellationToken);
                
                // Agregar a caché
                _playbooks[playbook.PlaybookId] = playbook;
                
                // Si es template, agregar a templates
                if (playbook.IsTemplate)
                {
                    var template = ConvertToTemplate(playbook);
                    _templates[template.TemplateId] = template;
                }
                
                _logger.LogInformation("Playbook creado exitosamente: {PlaybookId} - {PlaybookName}", 
                    playbook.PlaybookId, playbook.Name);
                
                // Emitir evento
                await EmitPlaybookEventAsync(new PlaybookEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = PlaybookEventType.Created,
                    PlaybookId = playbook.PlaybookId,
                    PlaybookName = playbook.Name,
                    UserId = createdBy,
                    Details = new { Request = request }
                });
                
                return playbook;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al crear playbook: {PlaybookName}", request.Name);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene un playbook por ID
        /// </summary>
        public async Task<PlaybookDefinition> GetPlaybookAsync(
            string playbookId, 
            bool includeCompiled = false,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(playbookId))
                throw new ArgumentNullException(nameof(playbookId));
            
            // Primero buscar en caché
            if (_playbooks.TryGetValue(playbookId, out var cachedPlaybook))
            {
                if (!includeCompiled)
                {
                    // Retornar copia sin steps compilados
                    return cachedPlaybook.CloneWithoutCompiled();
                }
                return cachedPlaybook;
            }
            
            // Si no está en caché, cargar desde repositorio
            try
            {
                var playbook = await _repository.GetPlaybookAsync(playbookId, cancellationToken);
                if (playbook == null)
                {
                    throw new PlaybookNotFoundException($"Playbook no encontrado: {playbookId}");
                }
                
                // Agregar a caché
                _playbooks[playbookId] = playbook;
                
                if (!includeCompiled)
                {
                    return playbook.CloneWithoutCompiled();
                }
                
                return playbook;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener playbook: {PlaybookId}", playbookId);
                throw;
            }
        }
        
        /// <summary>
        /// Actualiza un playbook existente
        /// </summary>
        public async Task<PlaybookDefinition> UpdatePlaybookAsync(
            string playbookId,
            PlaybookUpdateRequest request,
            string updatedBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(playbookId))
                throw new ArgumentNullException(nameof(playbookId));
            
            try
            {
                _logger.LogInformation("Actualizando playbook: {PlaybookId}", playbookId);
                
                // Obtener playbook existente
                var existingPlaybook = await GetPlaybookAsync(playbookId, true, cancellationToken);
                if (existingPlaybook == null)
                {
                    throw new PlaybookNotFoundException($"Playbook no encontrado: {playbookId}");
                }
                
                // Validar que no esté en ejecución
                if (IsPlaybookExecuting(playbookId))
                {
                    throw new PlaybookBusyException(
                        $"Playbook {playbookId} está en ejecución. No se puede actualizar.");
                }
                
                // Aplicar actualizaciones
                var updatedPlaybook = existingPlaybook.Clone();
                
                if (!string.IsNullOrEmpty(request.Name))
                    updatedPlaybook.Name = request.Name;
                
                if (!string.IsNullOrEmpty(request.Description))
                    updatedPlaybook.Description = request.Description;
                
                if (request.Category.HasValue)
                    updatedPlaybook.Category = request.Category.Value;
                
                if (request.Priority.HasValue)
                    updatedPlaybook.Priority = request.Priority.Value;
                
                if (request.TriggerConditions != null)
                    updatedPlaybook.TriggerConditions = request.TriggerConditions;
                
                if (request.Steps != null)
                    updatedPlaybook.Steps = request.Steps;
                
                if (request.Outputs != null)
                    updatedPlaybook.Outputs = request.Outputs;
                
                if (request.Metadata != null)
                    updatedPlaybook.Metadata = request.Metadata;
                
                if (request.ExecutionTimeout.HasValue)
                    updatedPlaybook.ExecutionTimeout = request.ExecutionTimeout.Value;
                
                if (request.MaxRetries.HasValue)
                    updatedPlaybook.MaxRetries = request.MaxRetries.Value;
                
                if (request.RetryDelay.HasValue)
                    updatedPlaybook.RetryDelay = request.RetryDelay.Value;
                
                if (request.IsActive.HasValue)
                    updatedPlaybook.IsActive = request.IsActive.Value;
                
                if (request.RequiresApproval.HasValue)
                    updatedPlaybook.RequiresApproval = request.RequiresApproval.Value;
                
                if (request.ApprovalWorkflow != null)
                    updatedPlaybook.ApprovalWorkflow = request.ApprovalWorkflow;
                
                // Incrementar versión
                updatedPlaybook.Version = IncrementVersion(existingPlaybook.Version);
                updatedPlaybook.UpdatedBy = updatedBy;
                updatedPlaybook.UpdatedAt = DateTime.UtcNow;
                
                // Re-compilar playbook
                var compilationResult = await _compiler.CompileAsync(updatedPlaybook, cancellationToken);
                if (!compilationResult.Success)
                {
                    throw new PlaybookCompilationException(
                        $"Error al compilar playbook actualizado: {compilationResult.ErrorMessage}");
                }
                
                updatedPlaybook.CompiledSteps = compilationResult.CompiledSteps;
                updatedPlaybook.ValidationErrors = compilationResult.ValidationErrors;
                updatedPlaybook.IsValid = compilationResult.IsValid;
                
                // Guardar en repositorio
                await _repository.SavePlaybookAsync(updatedPlaybook, cancellationToken);
                
                // Actualizar caché
                _playbooks[playbookId] = updatedPlaybook;
                
                _logger.LogInformation("Playbook actualizado exitosamente: {PlaybookId} v{Version}", 
                    updatedPlaybook.PlaybookId, updatedPlaybook.Version);
                
                // Emitir evento
                await EmitPlaybookEventAsync(new PlaybookEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = PlaybookEventType.Updated,
                    PlaybookId = updatedPlaybook.PlaybookId,
                    PlaybookName = updatedPlaybook.Name,
                    UserId = updatedBy,
                    Details = new 
                    { 
                        PreviousVersion = existingPlaybook.Version,
                        NewVersion = updatedPlaybook.Version,
                        Changes = request 
                    }
                });
                
                return updatedPlaybook;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al actualizar playbook: {PlaybookId}", playbookId);
                throw;
            }
        }
        
        /// <summary>
        /// Elimina un playbook
        /// </summary>
        public async Task<bool> DeletePlaybookAsync(
            string playbookId,
            string deletedBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(playbookId))
                throw new ArgumentNullException(nameof(playbookId));
            
            try
            {
                _logger.LogInformation("Eliminando playbook: {PlaybookId}", playbookId);
                
                // Verificar que exista
                var existingPlaybook = await GetPlaybookAsync(playbookId, false, cancellationToken);
                if (existingPlaybook == null)
                {
                    throw new PlaybookNotFoundException($"Playbook no encontrado: {playbookId}");
                }
                
                // Verificar que no esté en ejecución
                if (IsPlaybookExecuting(playbookId))
                {
                    throw new PlaybookBusyException(
                        $"Playbook {playbookId} está en ejecución. No se puede eliminar.");
                }
                
                // Marcar como inactivo (soft delete)
                existingPlaybook.IsActive = false;
                existingPlaybook.UpdatedBy = deletedBy;
                existingPlaybook.UpdatedAt = DateTime.UtcNow;
                
                // Actualizar en repositorio
                await _repository.SavePlaybookAsync(existingPlaybook, cancellationToken);
                
                // Remover de caché
                _playbooks.TryRemove(playbookId, out _);
                
                _logger.LogInformation("Playbook eliminado: {PlaybookId}", playbookId);
                
                // Emitir evento
                await EmitPlaybookEventAsync(new PlaybookEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = PlaybookEventType.Deleted,
                    PlaybookId = playbookId,
                    PlaybookName = existingPlaybook.Name,
                    UserId = deletedBy,
                    Details = new { SoftDelete = true }
                });
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al eliminar playbook: {PlaybookId}", playbookId);
                throw;
            }
        }
        
        /// <summary>
        /// Ejecuta un playbook
        /// </summary>
        public async Task<PlaybookExecution> ExecutePlaybookAsync(
            string playbookId,
            PlaybookExecutionContext context,
            string executedBy = null,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(playbookId))
                throw new ArgumentNullException(nameof(playbookId));
            
            if (context == null)
                throw new ArgumentNullException(nameof(context));
            
            try
            {
                _logger.LogInformation("Ejecutando playbook: {PlaybookId}", playbookId);
                
                // Obtener playbook
                var playbook = await GetPlaybookAsync(playbookId, true, cancellationToken);
                if (playbook == null)
                {
                    throw new PlaybookNotFoundException($"Playbook no encontrado: {playbookId}");
                }
                
                // Verificar que esté activo y válido
                if (!playbook.IsActive)
                {
                    throw new PlaybookInactiveException($"Playbook {playbookId} no está activo");
                }
                
                if (!playbook.IsValid)
                {
                    throw new PlaybookInvalidException(
                        $"Playbook {playbookId} no es válido: {string.Join(", ", playbook.ValidationErrors)}");
                }
                
                // Verificar condiciones de trigger
                var triggerResult = await EvaluateTriggerConditionsAsync(
                    playbook.TriggerConditions, context, cancellationToken);
                
                if (!triggerResult.ShouldExecute)
                {
                    _logger.LogInformation("Condiciones de trigger no cumplidas para playbook: {PlaybookId}", playbookId);
                    
                    return new PlaybookExecution
                    {
                        ExecutionId = GenerateExecutionId(),
                        PlaybookId = playbookId,
                        PlaybookName = playbook.Name,
                        Status = PlaybookExecutionStatus.Skipped,
                        TriggerEvaluation = triggerResult,
                        StartedAt = DateTime.UtcNow,
                        EndedAt = DateTime.UtcNow,
                        Context = context,
                        ExecutedBy = executedBy
                    };
                }
                
                // Si requiere aprobación, enviar a workflow
                if (playbook.RequiresApproval && playbook.ApprovalWorkflow != null)
                {
                    _logger.LogInformation("Playbook requiere aprobación: {PlaybookId}", playbookId);
                    
                    var approvalRequest = new ApprovalRequest
                    {
                        RequestId = GenerateApprovalRequestId(),
                        PlaybookId = playbookId,
                        PlaybookName = playbook.Name,
                        Context = context,
                        RequestedBy = executedBy,
                        RequestedAt = DateTime.UtcNow,
                        Priority = playbook.Priority,
                        Workflow = playbook.ApprovalWorkflow
                    };
                    
                    var approvalResult = await _approvalEngine.SubmitForApprovalAsync(
                        approvalRequest, cancellationToken);
                    
                    return new PlaybookExecution
                    {
                        ExecutionId = GenerateExecutionId(),
                        PlaybookId = playbookId,
                        PlaybookName = playbook.Name,
                        Status = PlaybookExecutionStatus.AwaitingApproval,
                        ApprovalRequest = approvalRequest,
                        TriggerEvaluation = triggerResult,
                        StartedAt = DateTime.UtcNow,
                        Context = context,
                        ExecutedBy = executedBy
                    };
                }
                
                // Crear ejecución
                var execution = new PlaybookExecution
                {
                    ExecutionId = GenerateExecutionId(),
                    PlaybookId = playbookId,
                    PlaybookName = playbook.Name,
                    PlaybookVersion = playbook.Version,
                    Status = PlaybookExecutionStatus.Running,
                    TriggerEvaluation = triggerResult,
                    StartedAt = DateTime.UtcNow,
                    Context = context,
                    ExecutedBy = executedBy,
                    Timeout = playbook.ExecutionTimeout,
                    MaxRetries = playbook.MaxRetries
                };
                
                // Registrar ejecución
                _executions[execution.ExecutionId] = execution;
                
                // Ejecutar en segundo plano
                _ = Task.Run(async () =>
                {
                    await ExecutePlaybookInternalAsync(execution, playbook, cancellationToken);
                }, cancellationToken);
                
                _logger.LogInformation("Playbook ejecución iniciada: {ExecutionId} para playbook {PlaybookId}", 
                    execution.ExecutionId, playbookId);
                
                return execution;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al ejecutar playbook: {PlaybookId}", playbookId);
                
                return new PlaybookExecution
                {
                    ExecutionId = GenerateExecutionId(),
                    PlaybookId = playbookId,
                    Status = PlaybookExecutionStatus.Failed,
                    Error = ex.Message,
                    StartedAt = DateTime.UtcNow,
                    EndedAt = DateTime.UtcNow,
                    Context = context,
                    ExecutedBy = executedBy
                };
            }
        }
        
        /// <summary>
        /// Obtiene estado de ejecución de un playbook
        /// </summary>
        public async Task<PlaybookExecution> GetExecutionStatusAsync(
            string executionId,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(executionId))
                throw new ArgumentNullException(nameof(executionId));
            
            // Buscar en caché
            if (_executions.TryGetValue(executionId, out var execution))
            {
                return execution;
            }
            
            // Buscar en repositorio
            try
            {
                return await _repository.GetExecutionAsync(executionId, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener estado de ejecución: {ExecutionId}", executionId);
                throw;
            }
        }
        
        /// <summary>
        /// Cancela una ejecución en curso
        /// </summary>
        public async Task<bool> CancelExecutionAsync(
            string executionId,
            string cancelledBy,
            string reason = null,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(executionId))
                throw new ArgumentNullException(nameof(executionId));
            
            try
            {
                _logger.LogInformation("Cancelando ejecución: {ExecutionId}", executionId);
                
                // Obtener ejecución
                var execution = await GetExecutionStatusAsync(executionId, cancellationToken);
                if (execution == null)
                {
                    throw new ExecutionNotFoundException($"Ejecución no encontrada: {executionId}");
                }
                
                // Verificar que se pueda cancelar
                if (execution.Status != PlaybookExecutionStatus.Running &&
                    execution.Status != PlaybookExecutionStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Ejecución {executionId} no se puede cancelar. Estado actual: {execution.Status}");
                }
                
                // Actualizar estado
                execution.Status = PlaybookExecutionStatus.Cancelled;
                execution.EndedAt = DateTime.UtcNow;
                execution.CancelledBy = cancelledBy;
                execution.CancellationReason = reason;
                
                // Guardar en repositorio
                await _repository.SaveExecutionAsync(execution, cancellationToken);
                
                // Actualizar caché
                _executions[executionId] = execution;
                
                // Cancelar acciones en curso
                await _orchestrator.CancelActionsAsync(executionId, cancellationToken);
                
                _logger.LogInformation("Ejecución cancelada: {ExecutionId}", executionId);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cancelar ejecución: {ExecutionId}", executionId);
                throw;
            }
        }
        
        /// <summary>
        /// Lista playbooks disponibles
        /// </summary>
        public async Task<PlaybookListResult> ListPlaybooksAsync(
            PlaybookListQuery query,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                return await _repository.ListPlaybooksAsync(query, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al listar playbooks");
                throw;
            }
        }
        
        /// <summary>
        /// Lista ejecuciones de playbooks
        /// </summary>
        public async Task<ExecutionListResult> ListExecutionsAsync(
            ExecutionListQuery query,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                return await _repository.ListExecutionsAsync(query, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al listar ejecuciones");
                throw;
            }
        }
        
        /// <summary>
        /// Crea un playbook a partir de un template
        /// </summary>
        public async Task<PlaybookDefinition> CreateFromTemplateAsync(
            string templateId,
            PlaybookTemplateParameters parameters,
            string createdBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(templateId))
                throw new ArgumentNullException(nameof(templateId));
            
            try
            {
                _logger.LogInformation("Creando playbook desde template: {TemplateId}", templateId);
                
                // Obtener template
                if (!_templates.TryGetValue(templateId, out var template))
                {
                    throw new TemplateNotFoundException($"Template no encontrado: {templateId}");
                }
                
                // Aplicar parámetros al template
                var playbookRequest = ApplyTemplateParameters(template, parameters);
                
                // Crear playbook
                var playbook = await CreatePlaybookAsync(playbookRequest, createdBy, cancellationToken);
                
                _logger.LogInformation("Playbook creado desde template: {PlaybookId} desde {TemplateId}", 
                    playbook.PlaybookId, templateId);
                
                return playbook;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al crear playbook desde template: {TemplateId}", templateId);
                throw;
            }
        }
        
        /// <summary>
        /// Exporta un playbook
        /// </summary>
        public async Task<PlaybookExport> ExportPlaybookAsync(
            string playbookId,
            ExportFormat format = ExportFormat.Json,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(playbookId))
                throw new ArgumentNullException(nameof(playbookId));
            
            try
            {
                var playbook = await GetPlaybookAsync(playbookId, false, cancellationToken);
                if (playbook == null)
                {
                    throw new PlaybookNotFoundException($"Playbook no encontrado: {playbookId}");
                }
                
                var export = new PlaybookExport
                {
                    PlaybookId = playbook.PlaybookId,
                    Name = playbook.Name,
                    Description = playbook.Description,
                    Version = playbook.Version,
                    Category = playbook.Category,
                    Priority = playbook.Priority,
                    TriggerConditions = playbook.TriggerConditions,
                    Steps = playbook.Steps,
                    Outputs = playbook.Outputs,
                    Metadata = playbook.Metadata,
                    ExportFormat = format,
                    ExportedAt = DateTime.UtcNow,
                    ExportVersion = "1.0"
                };
                
                // Serializar según formato
                export.Content = format switch
                {
                    ExportFormat.Json => JsonSerializer.Serialize(export, 
                        new JsonSerializerOptions { WriteIndented = true }),
                    
                    ExportFormat.Yaml => SerializeToYaml(export),
                    
                    _ => throw new NotSupportedException($"Formato no soportado: {format}")
                };
                
                return export;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al exportar playbook: {PlaybookId}", playbookId);
                throw;
            }
        }
        
        /// <summary>
        /// Importa un playbook
        /// </summary>
        public async Task<PlaybookDefinition> ImportPlaybookAsync(
            PlaybookImport import,
            string importedBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (import == null)
                throw new ArgumentNullException(nameof(import));
            
            try
            {
                _logger.LogInformation("Importando playbook: {PlaybookName}", import.Name);
                
                // Validar import
                var validationResult = await _validator.ValidateImportAsync(import, cancellationToken);
                if (!validationResult.IsValid)
                {
                    throw new PlaybookValidationException(
                        $"Importación inválida: {string.Join(", ", validationResult.Errors)}");
                }
                
                // Crear request de creación
                var createRequest = new PlaybookCreateRequest
                {
                    Name = import.Name,
                    Description = import.Description,
                    Category = import.Category,
                    Priority = import.Priority,
                    TriggerConditions = import.TriggerConditions,
                    Steps = import.Steps,
                    Outputs = import.Outputs,
                    Metadata = import.Metadata,
                    ExecutionTimeout = import.ExecutionTimeout,
                    MaxRetries = import.MaxRetries,
                    RetryDelay = import.RetryDelay,
                    RequiresApproval = import.RequiresApproval,
                    ApprovalWorkflow = import.ApprovalWorkflow
                };
                
                // Crear playbook
                var playbook = await CreatePlaybookAsync(createRequest, importedBy, cancellationToken);
                
                _logger.LogInformation("Playbook importado exitosamente: {PlaybookId}", playbook.PlaybookId);
                
                return playbook;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al importar playbook: {PlaybookName}", import?.Name);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del motor
        /// </summary>
        public async Task<PlaybookEngineStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                var stats = new PlaybookEngineStats
                {
                    Timestamp = DateTime.UtcNow,
                    TotalPlaybooks = _playbooks.Count,
                    ActivePlaybooks = _playbooks.Count(p => p.Value.IsActive),
                    TotalTemplates = _templates.Count,
                    ActiveExecutions = _executions.Count(e => 
                        e.Value.Status == PlaybookExecutionStatus.Running || 
                        e.Value.Status == PlaybookExecutionStatus.Pending),
                    
                    TotalExecutions = await _repository.GetTotalExecutionsAsync(cancellationToken),
                    SuccessfulExecutions = await _repository.GetSuccessfulExecutionsAsync(cancellationToken),
                    FailedExecutions = await _repository.GetFailedExecutionsAsync(cancellationToken),
                    
                    AverageExecutionTime = await _repository.GetAverageExecutionTimeAsync(cancellationToken),
                    MostExecutedPlaybooks = await _repository.GetMostExecutedPlaybooksAsync(10, cancellationToken),
                    
                    IsInitialized = _isInitialized,
                    Uptime = GetEngineUptime()
                };
                
                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener estadísticas del motor");
                throw;
            }
        }
        
        #region Métodos Privados
        
        private async Task LoadPlaybooksFromRepositoryAsync(CancellationToken cancellationToken)
        {
            try
            {
                var playbooks = await _repository.GetAllActivePlaybooksAsync(cancellationToken);
                
                foreach (var playbook in playbooks)
                {
                    _playbooks[playbook.PlaybookId] = playbook;
                    
                    if (playbook.IsTemplate)
                    {
                        var template = ConvertToTemplate(playbook);
                        _templates[template.TemplateId] = template;
                    }
                }
                
                _logger.LogDebug("Cargados {Count} playbooks desde repositorio", playbooks.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cargar playbooks desde repositorio");
                throw;
            }
        }
        
        private async Task LoadPredefinedTemplatesAsync(CancellationToken cancellationToken)
        {
            try
            {
                var predefinedTemplates = GetPredefinedTemplates();
                
                foreach (var template in predefinedTemplates)
                {
                    _templates[template.TemplateId] = template;
                }
                
                _logger.LogDebug("Cargados {Count} templates predefinidos", predefinedTemplates.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cargar templates predefinidos");
                // No lanzar excepción, solo log
            }
        }
        
        private void SubscribeToEvents()
        {
            // Suscribirse a eventos del orchestrator
            _orchestrator.ActionCompleted += OnActionCompleted;
            _orchestrator.ActionFailed += OnActionFailed;
            
            // Suscribirse a eventos de aprobación
            _approvalEngine.ApprovalGranted += OnApprovalGranted;
            _approvalEngine.ApprovalDenied += OnApprovalDenied;
            
            _logger.LogDebug("Suscripciones a eventos configuradas");
        }
        
        private async Task ExecutePlaybookInternalAsync(
            PlaybookExecution execution,
            PlaybookDefinition playbook,
            CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation("Ejecutando playbook internamente: {ExecutionId}", execution.ExecutionId);
                
                var steps = playbook.CompiledSteps;
                var context = execution.Context;
                var outputs = new Dictionary<string, object>();
                
                // Ejecutar cada paso
                for (int i = 0; i < steps.Count; i++)
                {
                    var step = steps[i];
                    
                    // Verificar timeout
                    if (execution.StartedAt.Add(execution.Timeout) < DateTime.UtcNow)
                    {
                        execution.Status = PlaybookExecutionStatus.Timeout;
                        execution.Error = $"Timeout después de {execution.Timeout}";
                        execution.EndedAt = DateTime.UtcNow;
                        break;
                    }
                    
                    // Verificar cancelación
                    if (cancellationToken.IsCancellationRequested)
                    {
                        execution.Status = PlaybookExecutionStatus.Cancelled;
                        execution.EndedAt = DateTime.UtcNow;
                        break;
                    }
                    
                    try
                    {
                        // Actualizar estado del paso
                        execution.CurrentStep = step.StepId;
                        execution.CurrentStepIndex = i;
                        execution.UpdatedAt = DateTime.UtcNow;
                        
                        // Ejecutar acción
                        var actionResult = await _orchestrator.ExecuteActionAsync(
                            step.ActionType,
                            step.Parameters,
                            context,
                            outputs,
                            cancellationToken);
                        
                        // Registrar resultado
                        execution.StepResults.Add(new StepResult
                        {
                            StepId = step.StepId,
                            StepName = step.Name,
                            ActionType = step.ActionType,
                            Status = actionResult.Success ? 
                                ActionExecutionStatus.Success : ActionExecutionStatus.Failed,
                            Result = actionResult.Result,
                            Error = actionResult.Error,
                            Duration = actionResult.Duration,
                            Timestamp = DateTime.UtcNow
                        });
                        
                        // Si falló y hay retries configurados
                        if (!actionResult.Success && step.MaxRetries > 0)
                        {
                            for (int retry = 1; retry <= step.MaxRetries; retry++)
                            {
                                _logger.LogWarning(
                                    "Reintentando paso {StepId}, intento {Retry}/{MaxRetries}", 
                                    step.StepId, retry, step.MaxRetries);
                                
                                await Task.Delay(step.RetryDelay, cancellationToken);
                                
                                var retryResult = await _orchestrator.ExecuteActionAsync(
                                    step.ActionType,
                                    step.Parameters,
                                    context,
                                    outputs,
                                    cancellationToken);
                                
                                if (retryResult.Success)
                                {
                                    execution.StepResults.Last().Status = ActionExecutionStatus.Success;
                                    execution.StepResults.Last().Result = retryResult.Result;
                                    execution.StepResults.Last().Error = null;
                                    break;
                                }
                            }
                        }
                        
                        // Si después de retries sigue fallando, evaluar condición de error
                        if (!execution.StepResults.Last().Success)
                        {
                            if (step.ErrorHandling == ErrorHandlingStrategy.Stop)
                            {
                                execution.Status = PlaybookExecutionStatus.Failed;
                                execution.Error = $"Paso {step.StepId} falló: {execution.StepResults.Last().Error}";
                                execution.EndedAt = DateTime.UtcNow;
                                break;
                            }
                            else if (step.ErrorHandling == ErrorHandlingStrategy.Continue)
                            {
                                // Continuar con siguiente paso
                                continue;
                            }
                        }
                        
                        // Agregar output si está configurado
                        if (!string.IsNullOrEmpty(step.OutputKey) && actionResult.Result != null)
                        {
                            outputs[step.OutputKey] = actionResult.Result;
                        }
                        
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error al ejecutar paso {StepId} del playbook", step.StepId);
                        
                        execution.StepResults.Add(new StepResult
                        {
                            StepId = step.StepId,
                            StepName = step.Name,
                            Status = ActionExecutionStatus.Failed,
                            Error = ex.Message,
                            Timestamp = DateTime.UtcNow
                        });
                        
                        if (step.ErrorHandling == ErrorHandlingStrategy.Stop)
                        {
                            execution.Status = PlaybookExecutionStatus.Failed;
                            execution.Error = $"Excepción en paso {step.StepId}: {ex.Message}";
                            execution.EndedAt = DateTime.UtcNow;
                            break;
                        }
                    }
                }
                
                // Si completó todos los pasos sin errores fatales
                if (execution.Status == PlaybookExecutionStatus.Running)
                {
                    execution.Status = PlaybookExecutionStatus.Completed;
                    execution.EndedAt = DateTime.UtcNow;
                    execution.Outputs = outputs;
                }
                
                // Guardar ejecución finalizada
                await _repository.SaveExecutionAsync(execution, cancellationToken);
                
                // Emitir evento de finalización
                await EmitPlaybookEventAsync(new PlaybookEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = execution.Status == PlaybookExecutionStatus.Completed ? 
                        PlaybookEventType.ExecutionCompleted : PlaybookEventType.ExecutionFailed,
                    PlaybookId = execution.PlaybookId,
                    ExecutionId = execution.ExecutionId,
                    Details = new 
                    { 
                        Status = execution.Status,
                        Duration = execution.EndedAt - execution.StartedAt,
                        StepsExecuted = execution.StepResults.Count
                    }
                });
                
                _logger.LogInformation("Ejecución de playbook finalizada: {ExecutionId} - Estado: {Status}", 
                    execution.ExecutionId, execution.Status);
                
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fatal en ejecución interna de playbook: {ExecutionId}", 
                    execution.ExecutionId);
                
                execution.Status = PlaybookExecutionStatus.Failed;
                execution.Error = $"Error fatal: {ex.Message}";
                execution.EndedAt = DateTime.UtcNow;
                
                await _repository.SaveExecutionAsync(execution, cancellationToken);
            }
        }
        
        private async Task<TriggerEvaluationResult> EvaluateTriggerConditionsAsync(
            List<TriggerCondition> conditions,
            PlaybookExecutionContext context,
            CancellationToken cancellationToken)
        {
            if (conditions == null || conditions.Count == 0)
            {
                return new TriggerEvaluationResult
                {
                    ShouldExecute = true,
                    MatchedConditions = new List<string>(),
                    EvaluationTime = DateTime.UtcNow
                };
            }
            
            var matchedConditions = new List<string>();
            
            foreach (var condition in conditions)
            {
                try
                {
                    var isMet = await EvaluateConditionAsync(condition, context, cancellationToken);
                    if (isMet)
                    {
                        matchedConditions.Add(condition.Name);
                    }
                    
                    // Si es condición AND y alguna no se cumple, retornar false
                    if (condition.Operator == ConditionOperator.And && !isMet)
                    {
                        return new TriggerEvaluationResult
                        {
                            ShouldExecute = false,
                            MatchedConditions = matchedConditions,
                            EvaluationTime = DateTime.UtcNow,
                            FailedCondition = condition.Name
                        };
                    }
                    
                    // Si es condición OR y alguna se cumple, retornar true
                    if (condition.Operator == ConditionOperator.Or && isMet)
                    {
                        return new TriggerEvaluationResult
                        {
                            ShouldExecute = true,
                            MatchedConditions = matchedConditions,
                            EvaluationTime = DateTime.UtcNow
                        };
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error al evaluar condición: {ConditionName}", condition.Name);
                }
            }
            
            // Para AND: todas deben cumplirse
            // Para OR: ninguna se cumplió (ya habría retornado true)
            return new TriggerEvaluationResult
            {
                ShouldExecute = conditions.All(c => c.Operator == ConditionOperator.And),
                MatchedConditions = matchedConditions,
                EvaluationTime = DateTime.UtcNow
            };
        }
        
        private async Task<bool> EvaluateConditionAsync(
            TriggerCondition condition,
            PlaybookExecutionContext context,
            CancellationToken cancellationToken)
        {
            // Implementar evaluación de condiciones según tipo
            switch (condition.Type)
            {
                case ConditionType.EventType:
                    return context.EventType == condition.Value;
                    
                case ConditionType.Severity:
                    if (int.TryParse(condition.Value, out int severity))
                    {
                        return context.Severity >= severity;
                    }
                    return false;
                    
                case ConditionType.Source:
                    return context.Source?.Contains(condition.Value, StringComparison.OrdinalIgnoreCase) == true;
                    
                case ConditionType.Custom:
                    return await EvaluateCustomConditionAsync(condition, context, cancellationToken);
                    
                default:
                    return false;
            }
        }
        
        private async Task<bool> EvaluateCustomConditionAsync(
            TriggerCondition condition,
            PlaybookExecutionContext context,
            CancellationToken cancellationToken)
        {
            // Implementar evaluación personalizada
            // Por ahora, retornar true para condiciones personalizadas
            await Task.CompletedTask;
            return true;
        }
        
        private async void OnActionCompleted(object sender, ActionCompletedEventArgs e)
        {
            try
            {
                // Buscar ejecución y actualizar estado
                if (_executions.TryGetValue(e.ExecutionId, out var execution))
                {
                    // Actualizar paso correspondiente
                    var stepResult = execution.StepResults
                        .FirstOrDefault(s => s.StepId == e.StepId);
                    
                    if (stepResult != null)
                    {
                        stepResult.Status = ActionExecutionStatus.Success;
                        stepResult.Result = e.Result;
                        stepResult.Duration = e.Duration;
                        stepResult.CompletedAt = DateTime.UtcNow;
                    }
                    
                    execution.UpdatedAt = DateTime.UtcNow;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en handler de acción completada");
            }
        }
        
        private async void OnActionFailed(object sender, ActionFailedEventArgs e)
        {
            try
            {
                if (_executions.TryGetValue(e.ExecutionId, out var execution))
                {
                    var stepResult = execution.StepResults
                        .FirstOrDefault(s => s.StepId == e.StepId);
                    
                    if (stepResult != null)
                    {
                        stepResult.Status = ActionExecutionStatus.Failed;
                        stepResult.Error = e.Error;
                        stepResult.Duration = e.Duration;
                        stepResult.CompletedAt = DateTime.UtcNow;
                    }
                    
                    execution.UpdatedAt = DateTime.UtcNow;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en handler de acción fallida");
            }
        }
        
        private async void OnApprovalGranted(object sender, ApprovalGrantedEventArgs e)
        {
            try
            {
                _logger.LogInformation("Aprobación concedida para ejecución: {ExecutionId}", e.ExecutionId);
                
                // Buscar ejecución pendiente y continuar
                var execution = await _repository.GetExecutionAsync(e.ExecutionId);
                if (execution != null && execution.Status == PlaybookExecutionStatus.AwaitingApproval)
                {
                    execution.Status = PlaybookExecutionStatus.Running;
                    execution.UpdatedAt = DateTime.UtcNow;
                    execution.ApprovedBy = e.ApprovedBy;
                    execution.ApprovedAt = DateTime.UtcNow;
                    
                    await _repository.SaveExecutionAsync(execution);
                    _executions[execution.ExecutionId] = execution;
                    
                    // Continuar ejecución
                    var playbook = await GetPlaybookAsync(execution.PlaybookId, true);
                    if (playbook != null)
                    {
                        _ = Task.Run(async () =>
                        {
                            await ExecutePlaybookInternalAsync(execution, playbook, CancellationToken.None);
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en handler de aprobación concedida");
            }
        }
        
        private async void OnApprovalDenied(object sender, ApprovalDeniedEventArgs e)
        {
            try
            {
                _logger.LogInformation("Aprobación denegada para ejecución: {ExecutionId}", e.ExecutionId);
                
                var execution = await _repository.GetExecutionAsync(e.ExecutionId);
                if (execution != null)
                {
                    execution.Status = PlaybookExecutionStatus.Rejected;
                    execution.EndedAt = DateTime.UtcNow;
                    execution.RejectedBy = e.RejectedBy;
                    execution.RejectionReason = e.Reason;
                    
                    await _repository.SaveExecutionAsync(execution);
                    _executions[execution.ExecutionId] = execution;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en handler de aprobación denegada");
            }
        }
        
        private async Task EmitPlaybookEventAsync(PlaybookEvent playbookEvent)
        {
            try
            {
                // Enviar a sistema de eventos
                // Por ahora, solo log
                _logger.LogInformation(
                    "Playbook Event: {EventType} - Playbook: {PlaybookId} - User: {UserId}",
                    playbookEvent.EventType, playbookEvent.PlaybookId, playbookEvent.UserId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al emitir evento de playbook");
            }
        }
        
        private bool IsPlaybookExecuting(string playbookId)
        {
            return _executions.Values.Any(e => 
                e.PlaybookId == playbookId && 
                (e.Status == PlaybookExecutionStatus.Running || 
                 e.Status == PlaybookExecutionStatus.Pending));
        }
        
        private string GeneratePlaybookId()
        {
            return $"PBK-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateExecutionId()
        {
            return $"EXE-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateApprovalRequestId()
        {
            return $"APR-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string IncrementVersion(string currentVersion)
        {
            if (string.IsNullOrEmpty(currentVersion))
                return "1.0.0";
            
            var parts = currentVersion.Split('.');
            if (parts.Length >= 3 && int.TryParse(parts[2], out int patch))
            {
                return $"{parts[0]}.{parts[1]}.{patch + 1}";
            }
            
            return currentVersion;
        }
        
        private PlaybookTemplate ConvertToTemplate(PlaybookDefinition playbook)
        {
            return new PlaybookTemplate
            {
                TemplateId = $"TMP-{playbook.PlaybookId}",
                Name = playbook.Name,
                Description = playbook.Description,
                Category = playbook.Category,
                BasePlaybookId = playbook.PlaybookId,
                Parameters = GetTemplateParameters(playbook),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };
        }
        
        private List<TemplateParameter> GetTemplateParameters(PlaybookDefinition playbook)
        {
            // Extraer parámetros del playbook para template
            var parameters = new List<TemplateParameter>();
            
            // Buscar variables en steps
            foreach (var step in playbook.Steps)
            {
                if (step.Parameters != null)
                {
                    foreach (var param in step.Parameters)
                    {
                        if (param.Value is string stringValue && 
                            stringValue.StartsWith("{{") && stringValue.EndsWith("}}"))
                        {
                            var paramName = stringValue.Trim('{', '}').Trim();
                            
                            parameters.Add(new TemplateParameter
                            {
                                Name = paramName,
                                Description = $"Parámetro para {step.Name}",
                                Type = ParameterType.String,
                                Required = true,
                                DefaultValue = ""
                            });
                        }
                    }
                }
            }
            
            return parameters;
        }
        
        private PlaybookCreateRequest ApplyTemplateParameters(
            PlaybookTemplate template, 
            PlaybookTemplateParameters parameters)
        {
            // Implementar aplicación de parámetros a template
            // Por ahora, retornar request básico
            return new PlaybookCreateRequest
            {
                Name = parameters.Name ?? template.Name,
                Description = template.Description,
                Category = template.Category,
                Priority = PlaybookPriority.Medium,
                IsTemplate = false
            };
        }
        
        private List<PlaybookTemplate> GetPredefinedTemplates()
        {
            return new List<PlaybookTemplate>
            {
                new PlaybookTemplate
                {
                    TemplateId = "TMP-MALWARE-RESPONSE",
                    Name = "Respuesta a Malware",
                    Description = "Playbook automatizado para respuesta a detección de malware",
                    Category = PlaybookCategory.IncidentResponse,
                    BasePlaybookId = "MALWARE-RESPONSE",
                    Parameters = new List<TemplateParameter>
                    {
                        new TemplateParameter
                        {
                            Name = "severity_threshold",
                            Description = "Umbral de severidad para activación",
                            Type = ParameterType.Integer,
                            Required = true,
                            DefaultValue = "7"
                        },
                        new TemplateParameter
                        {
                            Name = "quarantine_action",
                            Description = "Acción de cuarentena a realizar",
                            Type = ParameterType.String,
                            Required = true,
                            DefaultValue = "auto"
                        }
                    },
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                },
                
                new PlaybookTemplate
                {
                    TemplateId = "TMP-DATA-EXFILTRATION",
                    Name = "Detección de Exfiltración de Datos",
                    Description = "Respuesta automatizada a intentos de exfiltración de datos",
                    Category = PlaybookCategory.DataProtection,
                    BasePlaybookId = "DATA-EXFILTRATION",
                    Parameters = new List<TemplateParameter>
                    {
                        new TemplateParameter
                        {
                            Name = "data_sensitivity",
                            Description = "Nivel de sensibilidad de los datos",
                            Type = ParameterType.String,
                            Required = true,
                            DefaultValue = "high"
                        },
                        new TemplateParameter
                        {
                            Name = "block_external",
                            Description = "Bloquear conexiones externas",
                            Type = ParameterType.Boolean,
                            Required = true,
                            DefaultValue = "true"
                        }
                    },
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                }
            };
        }
        
        private string SerializeToYaml(PlaybookExport export)
        {
            // Implementar serialización YAML
            // Por ahora, retornar JSON como YAML
            return JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
        }
        
        private TimeSpan GetEngineUptime()
        {
            // Implementar cálculo de uptime
            return TimeSpan.FromMinutes(0);
        }
        
        private void ValidateInitialized()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException(
                    "PlaybookDefinitionEngine no está inicializado. Llame a InitializeAsync primero.");
            }
        }
        
        #endregion
    }
    
    #region Interfaces y Clases de Soporte
    
    public interface IPlaybookEngine
    {
        Task InitializeAsync(CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> CreatePlaybookAsync(
            PlaybookCreateRequest request, 
            string createdBy,
            CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> GetPlaybookAsync(
            string playbookId, 
            bool includeCompiled = false,
            CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> UpdatePlaybookAsync(
            string playbookId,
            PlaybookUpdateRequest request,
            string updatedBy,
            CancellationToken cancellationToken = default);
        Task<bool> DeletePlaybookAsync(
            string playbookId,
            string deletedBy,
            CancellationToken cancellationToken = default);
        Task<PlaybookExecution> ExecutePlaybookAsync(
            string playbookId,
            PlaybookExecutionContext context,
            string executedBy = null,
            CancellationToken cancellationToken = default);
        Task<PlaybookExecution> GetExecutionStatusAsync(
            string executionId,
            CancellationToken cancellationToken = default);
        Task<bool> CancelExecutionAsync(
            string executionId,
            string cancelledBy,
            string reason = null,
            CancellationToken cancellationToken = default);
        Task<PlaybookListResult> ListPlaybooksAsync(
            PlaybookListQuery query,
            CancellationToken cancellationToken = default);
        Task<ExecutionListResult> ListExecutionsAsync(
            ExecutionListQuery query,
            CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> CreateFromTemplateAsync(
            string templateId,
            PlaybookTemplateParameters parameters,
            string createdBy,
            CancellationToken cancellationToken = default);
        Task<PlaybookExport> ExportPlaybookAsync(
            string playbookId,
            ExportFormat format = ExportFormat.Json,
            CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> ImportPlaybookAsync(
            PlaybookImport import,
            string importedBy,
            CancellationToken cancellationToken = default);
        Task<PlaybookEngineStats> GetStatsAsync(CancellationToken cancellationToken = default);
    }
    
    public interface IPlaybookRepository
    {
        Task SavePlaybookAsync(PlaybookDefinition playbook, CancellationToken cancellationToken = default);
        Task<PlaybookDefinition> GetPlaybookAsync(string playbookId, CancellationToken cancellationToken = default);
        Task<List<PlaybookDefinition>> GetAllActivePlaybooksAsync(CancellationToken cancellationToken = default);
        Task SaveExecutionAsync(PlaybookExecution execution, CancellationToken cancellationToken = default);
        Task<PlaybookExecution> GetExecutionAsync(string executionId, CancellationToken cancellationToken = default);
        Task<PlaybookListResult> ListPlaybooksAsync(PlaybookListQuery query, CancellationToken cancellationToken = default);
        Task<ExecutionListResult> ListExecutionsAsync(ExecutionListQuery query, CancellationToken cancellationToken = default);
        Task<long> GetTotalExecutionsAsync(CancellationToken cancellationToken = default);
        Task<long> GetSuccessfulExecutionsAsync(CancellationToken cancellationToken = default);
        Task<long> GetFailedExecutionsAsync(CancellationToken cancellationToken = default);
        Task<TimeSpan> GetAverageExecutionTimeAsync(CancellationToken cancellationToken = default);
        Task<List<PlaybookExecutionStats>> GetMostExecutedPlaybooksAsync(int top, CancellationToken cancellationToken = default);
    }
    
    public interface IActionOrchestrator
    {
        event EventHandler<ActionCompletedEventArgs> ActionCompleted;
        event EventHandler<ActionFailedEventArgs> ActionFailed;
        
        Task<ActionExecutionResult> ExecuteActionAsync(
            string actionType,
            Dictionary<string, object> parameters,
            PlaybookExecutionContext context,
            Dictionary<string, object> outputs,
            CancellationToken cancellationToken = default);
        Task CancelActionsAsync(string executionId, CancellationToken cancellationToken = default);
    }
    
    public interface IApprovalEngine
    {
        event EventHandler<ApprovalGrantedEventArgs> ApprovalGranted;
        event EventHandler<ApprovalDeniedEventArgs> ApprovalDenied;
        
        Task<ApprovalRequest> SubmitForApprovalAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken = default);
        Task<bool> ApproveAsync(
            string requestId,
            string approvedBy,
            string comments = null,
            CancellationToken cancellationToken = default);
        Task<bool> DenyAsync(
            string requestId,
            string deniedBy,
            string reason,
            CancellationToken cancellationToken = default);
    }
    
    public class PlaybookDefinition
    {
        public string PlaybookId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Version { get; set; }
        public PlaybookCategory Category { get; set; }
        public PlaybookPriority Priority { get; set; }
        
        public List<TriggerCondition> TriggerConditions { get; set; }
        public List<PlaybookStep> Steps { get; set; }
        public List<PlaybookOutput> Outputs { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public string CreatedBy { get; set; }
        public DateTime CreatedAt { get; set; }
        public string UpdatedBy { get; set; }
        public DateTime UpdatedAt { get; set; }
        
        public bool IsActive { get; set; }
        public bool IsTemplate { get; set; }
        public bool RequiresApproval { get; set; }
        public ApprovalWorkflow ApprovalWorkflow { get; set; }
        
        public TimeSpan ExecutionTimeout { get; set; }
        public int MaxRetries { get; set; }
        public TimeSpan RetryDelay { get; set; }
        
        // Campos de compilación
        public List<CompiledStep> CompiledSteps { get; set; }
        public List<string> ValidationErrors { get; set; }
        public bool IsValid { get; set; }
        
        public PlaybookDefinition()
        {
            TriggerConditions = new List<TriggerCondition>();
            Steps = new List<PlaybookStep>();
            Outputs = new List<PlaybookOutput>();
            Metadata = new Dictionary<string, object>();
            CompiledSteps = new List<CompiledStep>();
            ValidationErrors = new List<string>();
            IsValid = false;
            ExecutionTimeout = TimeSpan.FromHours(1);
            MaxRetries = 3;
            RetryDelay = TimeSpan.FromSeconds(30);
        }
        
        public PlaybookDefinition Clone()
        {
            return (PlaybookDefinition)MemberwiseClone();
        }
        
        public PlaybookDefinition CloneWithoutCompiled()
        {
            var clone = Clone();
            clone.CompiledSteps = null;
            return clone;
        }
    }
    
    public class PlaybookExecution
    {
        public string ExecutionId { get; set; }
        public string PlaybookId { get; set; }
        public string PlaybookName { get; set; }
        public string PlaybookVersion { get; set; }
        public PlaybookExecutionStatus Status { get; set; }
        
        public PlaybookExecutionContext Context { get; set; }
        public TriggerEvaluationResult TriggerEvaluation { get; set; }
        public ApprovalRequest ApprovalRequest { get; set; }
        
        public string CurrentStep { get; set; }
        public int CurrentStepIndex { get; set; }
        public List<StepResult> StepResults { get; set; }
        public Dictionary<string, object> Outputs { get; set; }
        
        public string ExecutedBy { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? EndedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        
        public string Error { get; set; }
        public string CancelledBy { get; set; }
        public string CancellationReason { get; set; }
        public string ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
        public string RejectedBy { get; set; }
        public string RejectionReason { get; set; }
        
        public TimeSpan Timeout { get; set; }
        public int MaxRetries { get; set; }
        
        public PlaybookExecution()
        {
            StepResults = new List<StepResult>();
            Outputs = new Dictionary<string, object>();
            Status = PlaybookExecutionStatus.Pending;
        }
    }
    
    public class PlaybookTemplate
    {
        public string TemplateId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public PlaybookCategory Category { get; set; }
        public string BasePlaybookId { get; set; }
        public List<TemplateParameter> Parameters { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        
        public PlaybookTemplate()
        {
            Parameters = new List<TemplateParameter>();
        }
    }
    
    public enum PlaybookCategory
    {
        IncidentResponse,
        ThreatHunting,
        VulnerabilityManagement,
        Compliance,
        DataProtection,
        UserManagement,
        SystemMaintenance,
        Custom
    }
    
    public enum PlaybookPriority
    {
        Critical = 1,
        High = 2,
        Medium = 3,
        Low = 4
    }
    
    public enum PlaybookExecutionStatus
    {
        Pending,
        Running,
        Completed,
        Failed,
        Cancelled,
        Timeout,
        AwaitingApproval,
        Rejected,
        Skipped
    }
    
    public enum ExportFormat
    {
        Json,
        Yaml
    }
    
    #endregion
}