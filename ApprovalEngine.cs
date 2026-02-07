using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BWP.Enterprise.Cloud.SOAR
{
    /// <summary>
    /// Motor de aprobaciones para flujos de trabajo SOAR
    /// Maneja aprobaciones manuales, multi-nivel, con tiempos de expiración y notificaciones
    /// </summary>
    public sealed class ApprovalEngine : IApprovalEngine, IDisposable
    {
        private readonly ILogger<ApprovalEngine> _logger;
        private readonly IApprovalRepository _repository;
        private readonly INotificationService _notificationService;
        private readonly IUserDirectory _userDirectory;
        
        private readonly ConcurrentDictionary<string, ApprovalRequest> _activeRequests;
        private readonly ConcurrentDictionary<string, Timer> _expirationTimers;
        private readonly ConcurrentDictionary<string, List<ApprovalListener>> _listeners;
        
        private readonly ApprovalWorkflowManager _workflowManager;
        private readonly ApprovalEscalationManager _escalationManager;
        private readonly ApprovalAuditLogger _auditLogger;
        
        private bool _isInitialized;
        private bool _isDisposed;
        private readonly SemaphoreSlim _initLock = new SemaphoreSlim(1, 1);
        
        public event EventHandler<ApprovalGrantedEventArgs> ApprovalGranted;
        public event EventHandler<ApprovalDeniedEventArgs> ApprovalDenied;
        public event EventHandler<ApprovalEscalatedEventArgs> ApprovalEscalated;
        public event EventHandler<ApprovalExpiredEventArgs> ApprovalExpired;
        public event EventHandler<ApprovalReminderEventArgs> ApprovalReminder;
        
        public ApprovalEngine(
            ILogger<ApprovalEngine> logger,
            IApprovalRepository repository = null,
            INotificationService notificationService = null,
            IUserDirectory userDirectory = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _repository = repository;
            _notificationService = notificationService;
            _userDirectory = userDirectory;
            
            _activeRequests = new ConcurrentDictionary<string, ApprovalRequest>();
            _expirationTimers = new ConcurrentDictionary<string, Timer>();
            _listeners = new ConcurrentDictionary<string, List<ApprovalListener>>();
            
            _workflowManager = new ApprovalWorkflowManager();
            _escalationManager = new ApprovalEscalationManager();
            _auditLogger = new ApprovalAuditLogger();
            
            _isInitialized = false;
            _isDisposed = false;
        }
        
        /// <summary>
        /// Inicializa el motor de aprobaciones
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            await _initLock.WaitAsync(cancellationToken);
            
            try
            {
                if (_isInitialized)
                    return;
                
                _logger.LogInformation("Inicializando ApprovalEngine...");
                
                // Inicializar componentes internos
                await _workflowManager.InitializeAsync(cancellationToken);
                await _escalationManager.InitializeAsync(cancellationToken);
                await _auditLogger.InitializeAsync(cancellationToken);
                
                // Cargar solicitudes activas desde el repositorio
                await LoadActiveRequestsAsync(cancellationToken);
                
                // Configurar timers de expiración para solicitudes activas
                SetupExpirationTimers();
                
                _isInitialized = true;
                _logger.LogInformation($"ApprovalEngine inicializado: {_activeRequests.Count} solicitudes activas");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al inicializar ApprovalEngine");
                throw;
            }
            finally
            {
                _initLock.Release();
            }
        }
        
        /// <summary>
        /// Envía una solicitud para aprobación
        /// </summary>
        public async Task<ApprovalRequest> SubmitForApprovalAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            
            try
            {
                _logger.LogInformation("Enviando solicitud de aprobación: {RequestId}, Playbook: {PlaybookId}", 
                    request.RequestId, request.PlaybookId);
                
                // Validar solicitud
                var validationResult = await ValidateRequestAsync(request, cancellationToken);
                if (!validationResult.IsValid)
                {
                    throw new ApprovalValidationException(
                        $"Solicitud de aprobación inválida: {string.Join(", ", validationResult.Errors)}");
                }
                
                // Generar ID si no existe
                if (string.IsNullOrEmpty(request.RequestId))
                {
                    request.RequestId = GenerateRequestId();
                }
                
                // Establecer timestamps
                request.CreatedAt = DateTime.UtcNow;
                request.UpdatedAt = DateTime.UtcNow;
                request.Status = ApprovalStatus.Pending;
                
                // Si no hay workflow, usar aprobación simple
                if (request.Workflow == null || request.Workflow.Steps.Count == 0)
                {
                    request.Workflow = CreateSimpleWorkflow(request);
                }
                
                // Inicializar workflow
                await InitializeWorkflowAsync(request, cancellationToken);
                
                // Si requiere aprobación inmediata del solicitante
                if (request.RequiresSelfApproval && 
                    !string.IsNullOrEmpty(request.RequestedBy))
                {
                    var selfApprovalResult = await ProcessSelfApprovalAsync(request, cancellationToken);
                    if (!selfApprovalResult.RequiresFurtherApproval)
                    {
                        request.Status = selfApprovalResult.Approved ? 
                            ApprovalStatus.Approved : ApprovalStatus.Denied;
                        request.CompletedAt = DateTime.UtcNow;
                        
                        await FinalizeRequestAsync(request, cancellationToken);
                        return request;
                    }
                }
                
                // Determinar aprobadores actuales
                await DetermineCurrentApproversAsync(request, cancellationToken);
                
                // Si no hay aprobadores, auto-aprobar
                if (request.CurrentApprovers.Count == 0)
                {
                    _logger.LogWarning("No hay aprobadores para solicitud {RequestId}, auto-aprobando", request.RequestId);
                    
                    request.Status = ApprovalStatus.AutoApproved;
                    request.CompletedAt = DateTime.UtcNow;
                    request.AutoApprovalReason = "No approvers configured";
                    
                    await FinalizeRequestAsync(request, cancellationToken);
                    return request;
                }
                
                // Guardar en repositorio
                if (_repository != null)
                {
                    await _repository.SaveRequestAsync(request, cancellationToken);
                }
                
                // Agregar a solicitudes activas
                _activeRequests[request.RequestId] = request;
                
                // Configurar timer de expiración
                SetupExpirationTimer(request);
                
                // Enviar notificaciones a aprobadores
                await NotifyApproversAsync(request, cancellationToken);
                
                // Registrar en auditoría
                await _auditLogger.LogSubmissionAsync(request, cancellationToken);
                
                _logger.LogInformation("Solicitud de aprobación enviada: {RequestId}, Aprobadores: {ApproverCount}", 
                    request.RequestId, request.CurrentApprovers.Count);
                
                return request;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar solicitud de aprobación: {PlaybookId}", request.PlaybookId);
                throw;
            }
        }
        
        /// <summary>
        /// Aprueba una solicitud
        /// </summary>
        public async Task<bool> ApproveAsync(
            string requestId,
            string approvedBy,
            string comments = null,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (string.IsNullOrEmpty(approvedBy))
                throw new ArgumentNullException(nameof(approvedBy));
            
            try
            {
                _logger.LogInformation("Procesando aprobación: {RequestId}, User: {UserId}", requestId, approvedBy);
                
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Validar estado
                if (request.Status != ApprovalStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Solicitud {requestId} no está pendiente. Estado actual: {request.Status}");
                }
                
                // Validar que el usuario puede aprobar
                var canApprove = await CanUserApproveAsync(request, approvedBy, cancellationToken);
                if (!canApprove)
                {
                    throw new UnauthorizedApprovalException(
                        $"Usuario {approvedBy} no tiene permisos para aprobar solicitud {requestId}");
                }
                
                // Registrar aprobación
                var approval = new ApprovalDecision
                {
                    DecisionId = GenerateDecisionId(),
                    RequestId = requestId,
                    Decision = ApprovalDecisionType.Approve,
                    DecidedBy = approvedBy,
                    Comments = comments,
                    DecidedAt = DateTime.UtcNow
                };
                
                request.Approvals.Add(approval);
                request.UpdatedAt = DateTime.UtcNow;
                
                // Registrar en auditoría
                await _auditLogger.LogDecisionAsync(approval, cancellationToken);
                
                // Verificar si se completó el nivel actual
                var levelComplete = await CheckLevelCompletionAsync(request, cancellationToken);
                if (levelComplete)
                {
                    // Avanzar al siguiente nivel o completar
                    await AdvanceToNextLevelOrCompleteAsync(request, true, cancellationToken);
                }
                else
                {
                    // Actualizar aprobadores actuales
                    await UpdateCurrentApproversAsync(request, cancellationToken);
                    
                    // Guardar cambios
                    await SaveRequestAsync(request, cancellationToken);
                    
                    _logger.LogInformation("Aprobación parcial registrada: {RequestId}, User: {UserId}", 
                        requestId, approvedBy);
                }
                
                // Emitir evento
                OnApprovalGranted(new ApprovalGrantedEventArgs
                {
                    RequestId = requestId,
                    PlaybookId = request.PlaybookId,
                    ExecutionId = request.ExecutionId,
                    ApprovedBy = approvedBy,
                    Comments = comments,
                    Timestamp = DateTime.UtcNow
                });
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al procesar aprobación: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Deniega una solicitud
        /// </summary>
        public async Task<bool> DenyAsync(
            string requestId,
            string deniedBy,
            string reason,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (string.IsNullOrEmpty(deniedBy))
                throw new ArgumentNullException(nameof(deniedBy));
            
            if (string.IsNullOrEmpty(reason))
                throw new ArgumentNullException(nameof(reason));
            
            try
            {
                _logger.LogInformation("Procesando denegación: {RequestId}, User: {UserId}, Reason: {Reason}", 
                    requestId, deniedBy, reason);
                
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Validar estado
                if (request.Status != ApprovalStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Solicitud {requestId} no está pendiente. Estado actual: {request.Status}");
                }
                
                // Validar que el usuario puede denegar
                var canDeny = await CanUserApproveAsync(request, deniedBy, cancellationToken);
                if (!canDeny)
                {
                    throw new UnauthorizedApprovalException(
                        $"Usuario {deniedBy} no tiene permisos para denegar solicitud {requestId}");
                }
                
                // Registrar denegación
                var decision = new ApprovalDecision
                {
                    DecisionId = GenerateDecisionId(),
                    RequestId = requestId,
                    Decision = ApprovalDecisionType.Deny,
                    DecidedBy = deniedBy,
                    Comments = reason,
                    DecidedAt = DateTime.UtcNow
                };
                
                request.Denials.Add(decision);
                request.Status = ApprovalStatus.Denied;
                request.CompletedAt = DateTime.UtcNow;
                request.UpdatedAt = DateTime.UtcNow;
                request.DenialReason = reason;
                
                // Cancelar timer de expiración
                CancelExpirationTimer(requestId);
                
                // Remover de solicitudes activas
                _activeRequests.TryRemove(requestId, out _);
                
                // Guardar cambios
                await SaveRequestAsync(request, cancellationToken);
                
                // Registrar en auditoría
                await _auditLogger.LogDecisionAsync(decision, cancellationToken);
                
                // Notificar al solicitante
                await NotifyRequesterAsync(request, false, reason, cancellationToken);
                
                // Emitir evento
                OnApprovalDenied(new ApprovalDeniedEventArgs
                {
                    RequestId = requestId,
                    PlaybookId = request.PlaybookId,
                    ExecutionId = request.ExecutionId,
                    RejectedBy = deniedBy,
                    Reason = reason,
                    Timestamp = DateTime.UtcNow
                });
                
                _logger.LogInformation("Solicitud denegada: {RequestId}, Reason: {Reason}", requestId, reason);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al procesar denegación: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene una solicitud de aprobación
        /// </summary>
        public async Task<ApprovalRequest> GetRequestAsync(
            string requestId, 
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            // Buscar en cache
            if (_activeRequests.TryGetValue(requestId, out var cachedRequest))
            {
                return cachedRequest;
            }
            
            // Buscar en repositorio
            if (_repository != null)
            {
                return await _repository.GetRequestAsync(requestId, cancellationToken);
            }
            
            return null;
        }
        
        /// <summary>
        /// Lista solicitudes de aprobación
        /// </summary>
        public async Task<ApprovalListResult> ListRequestsAsync(
            ApprovalListQuery query,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                var result = new ApprovalListResult
                {
                    Query = query,
                    TotalCount = 0,
                    Requests = new List<ApprovalRequest>()
                };
                
                if (_repository != null)
                {
                    return await _repository.ListRequestsAsync(query, cancellationToken);
                }
                
                // Si no hay repositorio, usar cache
                var allRequests = _activeRequests.Values.ToList();
                
                // Aplicar filtros
                var filtered = allRequests.AsQueryable();
                
                if (!string.IsNullOrEmpty(query.RequestedBy))
                {
                    filtered = filtered.Where(r => r.RequestedBy == query.RequestedBy);
                }
                
                if (query.Status.HasValue)
                {
                    filtered = filtered.Where(r => r.Status == query.Status.Value);
                }
                
                if (query.FromDate.HasValue)
                {
                    filtered = filtered.Where(r => r.CreatedAt >= query.FromDate.Value);
                }
                
                if (query.ToDate.HasValue)
                {
                    filtered = filtered.Where(r => r.CreatedAt <= query.ToDate.Value);
                }
                
                if (!string.IsNullOrEmpty(query.PlaybookId))
                {
                    filtered = filtered.Where(r => r.PlaybookId == query.PlaybookId);
                }
                
                // Ordenar
                filtered = query.SortOrder == SortOrder.Ascending ?
                    filtered.OrderBy(r => r.CreatedAt) :
                    filtered.OrderByDescending(r => r.CreatedAt);
                
                // Paginar
                result.TotalCount = filtered.Count();
                result.Requests = filtered
                    .Skip(query.PageIndex * query.PageSize)
                    .Take(query.PageSize)
                    .ToList();
                
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al listar solicitudes de aprobación");
                throw;
            }
        }
        
        /// <summary>
        /// Cancela una solicitud de aprobación
        /// </summary>
        public async Task<bool> CancelRequestAsync(
            string requestId,
            string cancelledBy,
            string reason = null,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (string.IsNullOrEmpty(cancelledBy))
                throw new ArgumentNullException(nameof(cancelledBy));
            
            try
            {
                _logger.LogInformation("Cancelando solicitud: {RequestId}, User: {UserId}", requestId, cancelledBy);
                
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Validar que puede ser cancelada
                if (request.Status != ApprovalStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Solicitud {requestId} no puede ser cancelada. Estado actual: {request.Status}");
                }
                
                // Validar que el usuario puede cancelar
                var canCancel = await CanUserCancelAsync(request, cancelledBy, cancellationToken);
                if (!canCancel)
                {
                    throw new UnauthorizedApprovalException(
                        $"Usuario {cancelledBy} no tiene permisos para cancelar solicitud {requestId}");
                }
                
                // Actualizar estado
                request.Status = ApprovalStatus.Cancelled;
                request.CompletedAt = DateTime.UtcNow;
                request.UpdatedAt = DateTime.UtcNow;
                request.CancelledBy = cancelledBy;
                request.CancellationReason = reason;
                
                // Cancelar timer de expiración
                CancelExpirationTimer(requestId);
                
                // Remover de solicitudes activas
                _activeRequests.TryRemove(requestId, out _);
                
                // Guardar cambios
                await SaveRequestAsync(request, cancellationToken);
                
                // Registrar en auditoría
                await _auditLogger.LogCancellationAsync(request, cancelledBy, reason, cancellationToken);
                
                // Notificar a aprobadores
                await NotifyApproversOfCancellationAsync(request, cancelledBy, reason, cancellationToken);
                
                _logger.LogInformation("Solicitud cancelada: {RequestId}, Reason: {Reason}", requestId, reason);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cancelar solicitud: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Escala una solicitud de aprobación
        /// </summary>
        public async Task<bool> EscalateRequestAsync(
            string requestId,
            string escalatedBy,
            string reason,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (string.IsNullOrEmpty(escalatedBy))
                throw new ArgumentNullException(nameof(escalatedBy));
            
            try
            {
                _logger.LogInformation("Escalando solicitud: {RequestId}, User: {UserId}", requestId, escalatedBy);
                
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Validar estado
                if (request.Status != ApprovalStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Solicitud {requestId} no está pendiente. Estado actual: {request.Status}");
                }
                
                // Registrar escalación
                var escalation = new ApprovalEscalation
                {
                    EscalationId = GenerateEscalationId(),
                    RequestId = requestId,
                    EscalatedBy = escalatedBy,
                    Reason = reason,
                    EscalatedAt = DateTime.UtcNow,
                    PreviousLevel = request.CurrentStepIndex,
                    NewLevel = request.CurrentStepIndex + 1
                };
                
                request.Escalations.Add(escalation);
                request.UpdatedAt = DateTime.UtcNow;
                
                // Mover al siguiente nivel
                await AdvanceToNextLevelAsync(request, cancellationToken);
                
                // Registrar en auditoría
                await _auditLogger.LogEscalationAsync(escalation, cancellationToken);
                
                // Emitir evento
                OnApprovalEscalated(new ApprovalEscalatedEventArgs
                {
                    RequestId = requestId,
                    PlaybookId = request.PlaybookId,
                    EscalatedBy = escalatedBy,
                    Reason = reason,
                    FromLevel = escalation.PreviousLevel,
                    ToLevel = escalation.NewLevel,
                    Timestamp = DateTime.UtcNow
                });
                
                _logger.LogInformation("Solicitud escalada: {RequestId}, From Level: {FromLevel}, To Level: {ToLevel}", 
                    requestId, escalation.PreviousLevel, escalation.NewLevel);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al escalar solicitud: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Añade un comentario a una solicitud
        /// </summary>
        public async Task<bool> AddCommentAsync(
            string requestId,
            string userId,
            string comment,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentNullException(nameof(userId));
            
            if (string.IsNullOrEmpty(comment))
                throw new ArgumentNullException(nameof(comment));
            
            try
            {
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Agregar comentario
                var commentObj = new ApprovalComment
                {
                    CommentId = GenerateCommentId(),
                    RequestId = requestId,
                    UserId = userId,
                    Comment = comment,
                    CreatedAt = DateTime.UtcNow
                };
                
                request.Comments.Add(commentObj);
                request.UpdatedAt = DateTime.UtcNow;
                
                // Guardar cambios
                await SaveRequestAsync(request, cancellationToken);
                
                // Registrar en auditoría
                await _auditLogger.LogCommentAsync(commentObj, cancellationToken);
                
                _logger.LogDebug("Comentario agregado a solicitud {RequestId} por usuario {UserId}", requestId, userId);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al agregar comentario a solicitud: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Registra un listener para una solicitud
        /// </summary>
        public async Task<string> RegisterListenerAsync(
            string requestId,
            ApprovalListener listener,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            if (listener == null)
                throw new ArgumentNullException(nameof(listener));
            
            try
            {
                var listenerId = GenerateListenerId();
                
                if (!_listeners.ContainsKey(requestId))
                {
                    _listeners[requestId] = new List<ApprovalListener>();
                }
                
                _listeners[requestId].Add(listener);
                
                _logger.LogDebug("Listener registrado para solicitud {RequestId}: {ListenerId}", requestId, listenerId);
                
                return listenerId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al registrar listener para solicitud: {RequestId}", requestId);
                throw;
            }
        }
        
        /// <summary>
        /// Obtiene estadísticas del motor
        /// </summary>
        public async Task<ApprovalEngineStats> GetStatsAsync(CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            try
            {
                var stats = new ApprovalEngineStats
                {
                    Timestamp = DateTime.UtcNow,
                    TotalRequests = await GetTotalRequestCountAsync(cancellationToken),
                    ActiveRequests = _activeRequests.Count,
                    PendingRequests = _activeRequests.Count(r => r.Value.Status == ApprovalStatus.Pending),
                    
                    AverageApprovalTime = await GetAverageApprovalTimeAsync(cancellationToken),
                    ApprovalRate = await GetApprovalRateAsync(cancellationToken),
                    
                    TotalEscalations = await GetTotalEscalationsAsync(cancellationToken),
                    TotalComments = await GetTotalCommentsAsync(cancellationToken),
                    
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
        
        /// <summary>
        /// Obtiene solicitudes pendientes para un usuario
        /// </summary>
        public async Task<List<ApprovalRequest>> GetPendingRequestsForUserAsync(
            string userId,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(userId))
                throw new ArgumentNullException(nameof(userId));
            
            try
            {
                var pendingRequests = new List<ApprovalRequest>();
                
                foreach (var request in _activeRequests.Values)
                {
                    if (request.Status == ApprovalStatus.Pending)
                    {
                        // Verificar si el usuario es aprobador actual
                        if (request.CurrentApprovers.Any(a => a.UserId == userId))
                        {
                            pendingRequests.Add(request);
                        }
                    }
                }
                
                return pendingRequests;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener solicitudes pendientes para usuario: {UserId}", userId);
                throw;
            }
        }
        
        /// <summary>
        /// Envía recordatorio para una solicitud
        /// </summary>
        public async Task<bool> SendReminderAsync(
            string requestId,
            string sentBy,
            CancellationToken cancellationToken = default)
        {
            ValidateInitialized();
            
            if (string.IsNullOrEmpty(requestId))
                throw new ArgumentNullException(nameof(requestId));
            
            try
            {
                _logger.LogInformation("Enviando recordatorio para solicitud: {RequestId}, SentBy: {UserId}", 
                    requestId, sentBy);
                
                // Obtener solicitud
                var request = await GetRequestAsync(requestId, cancellationToken);
                if (request == null)
                {
                    throw new ApprovalNotFoundException($"Solicitud de aprobación no encontrada: {requestId}");
                }
                
                // Validar estado
                if (request.Status != ApprovalStatus.Pending)
                {
                    throw new InvalidOperationException(
                        $"Solicitud {requestId} no está pendiente. Estado actual: {request.Status}");
                }
                
                // Enviar recordatorio a aprobadores actuales
                await SendReminderToApproversAsync(request, sentBy, cancellationToken);
                
                // Registrar recordatorio
                request.ReminderCount++;
                request.LastReminderAt = DateTime.UtcNow;
                request.UpdatedAt = DateTime.UtcNow;
                
                await SaveRequestAsync(request, cancellationToken);
                
                // Emitir evento
                OnApprovalReminder(new ApprovalReminderEventArgs
                {
                    RequestId = requestId,
                    PlaybookId = request.PlaybookId,
                    SentBy = sentBy,
                    ReminderCount = request.ReminderCount,
                    Timestamp = DateTime.UtcNow
                });
                
                _logger.LogInformation("Recordatorio enviado para solicitud: {RequestId}", requestId);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar recordatorio para solicitud: {RequestId}", requestId);
                throw;
            }
        }
        
        public void Dispose()
        {
            if (_isDisposed)
                return;
            
            _isDisposed = true;
            
            // Detener todos los timers
            foreach (var timer in _expirationTimers.Values)
            {
                timer?.Dispose();
            }
            
            _expirationTimers.Clear();
            _activeRequests.Clear();
            _listeners.Clear();
            
            // Dispose de componentes
            _workflowManager?.Dispose();
            _escalationManager?.Dispose();
            _auditLogger?.Dispose();
            
            GC.SuppressFinalize(this);
        }
        
        #region Métodos Privados
        
        private async Task LoadActiveRequestsAsync(CancellationToken cancellationToken)
        {
            try
            {
                if (_repository != null)
                {
                    var activeRequests = await _repository.GetActiveRequestsAsync(cancellationToken);
                    
                    foreach (var request in activeRequests)
                    {
                        _activeRequests[request.RequestId] = request;
                    }
                    
                    _logger.LogDebug("Cargadas {Count} solicitudes activas desde repositorio", activeRequests.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cargar solicitudes activas desde repositorio");
                throw;
            }
        }
        
        private void SetupExpirationTimers()
        {
            foreach (var request in _activeRequests.Values)
            {
                if (request.Status == ApprovalStatus.Pending && 
                    request.ExpiresAt.HasValue && 
                    request.ExpiresAt > DateTime.UtcNow)
                {
                    SetupExpirationTimer(request);
                }
            }
        }
        
        private void SetupExpirationTimer(ApprovalRequest request)
        {
            if (!request.ExpiresAt.HasValue || request.ExpiresAt <= DateTime.UtcNow)
            {
                return;
            }
            
            var timeUntilExpiration = request.ExpiresAt.Value - DateTime.UtcNow;
            
            // Configurar timer para expiración
            var timer = new Timer(async _ =>
            {
                await HandleRequestExpirationAsync(request.RequestId);
            }, null, timeUntilExpiration, Timeout.InfiniteTimeSpan);
            
            _expirationTimers[request.RequestId] = timer;
            
            _logger.LogDebug("Timer de expiración configurado para solicitud {RequestId}: {ExpiresAt}", 
                request.RequestId, request.ExpiresAt);
        }
        
        private async Task HandleRequestExpirationAsync(string requestId)
        {
            try
            {
                _logger.LogInformation("Manejando expiración de solicitud: {RequestId}", requestId);
                
                var request = await GetRequestAsync(requestId);
                if (request == null || request.Status != ApprovalStatus.Pending)
                {
                    return;
                }
                
                // Marcar como expirada
                request.Status = ApprovalStatus.Expired;
                request.CompletedAt = DateTime.UtcNow;
                request.UpdatedAt = DateTime.UtcNow;
                request.ExpirationReason = "Request expired without approval";
                
                // Remover de activas
                _activeRequests.TryRemove(requestId, out _);
                
                // Guardar cambios
                await SaveRequestAsync(request);
                
                // Notificar al solicitante
                await NotifyRequesterAsync(request, false, "Request expired without approval", CancellationToken.None);
                
                // Emitir evento
                OnApprovalExpired(new ApprovalExpiredEventArgs
                {
                    RequestId = requestId,
                    PlaybookId = request.PlaybookId,
                    ExpiredAt = DateTime.UtcNow,
                    Reason = "Request expired without approval"
                });
                
                _logger.LogInformation("Solicitud expirada: {RequestId}", requestId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al manejar expiración de solicitud: {RequestId}", requestId);
            }
        }
        
        private void CancelExpirationTimer(string requestId)
        {
            if (_expirationTimers.TryRemove(requestId, out var timer))
            {
                timer?.Dispose();
            }
        }
        
        private async Task<ValidationResult> ValidateRequestAsync(
            ApprovalRequest request, 
            CancellationToken cancellationToken)
        {
            var errors = new List<string>();
            
            if (string.IsNullOrEmpty(request.PlaybookId))
                errors.Add("PlaybookId is required");
            
            if (string.IsNullOrEmpty(request.PlaybookName))
                errors.Add("PlaybookName is required");
            
            if (string.IsNullOrEmpty(request.RequestedBy))
                errors.Add("RequestedBy is required");
            
            if (request.Context == null)
                errors.Add("Context is required");
            
            if (request.Priority == ApprovalPriority.None)
                errors.Add("Priority is required");
            
            if (errors.Count > 0)
            {
                return ValidationResult.Error(errors);
            }
            
            return ValidationResult.Success();
        }
        
        private ApprovalWorkflow CreateSimpleWorkflow(ApprovalRequest request)
        {
            return new ApprovalWorkflow
            {
                WorkflowId = GenerateWorkflowId(),
                Name = $"Simple Workflow for {request.PlaybookName}",
                Description = "Single-level approval workflow",
                Steps = new List<ApprovalWorkflowStep>
                {
                    new ApprovalWorkflowStep
                    {
                        StepIndex = 0,
                        Name = "Initial Approval",
                        Description = "Initial approval step",
                        RequiredApprovals = 1,
                        Approvers = new List<ApproverDefinition>(),
                        Timeout = TimeSpan.FromHours(24),
                        CanEscalate = true,
                        EscalationTimeout = TimeSpan.FromHours(12)
                    }
                }
            };
        }
        
        private async Task InitializeWorkflowAsync(ApprovalRequest request, CancellationToken cancellationToken)
        {
            // Inicializar workflow
            request.CurrentStepIndex = 0;
            request.CurrentStep = request.Workflow.Steps[0];
            request.TotalSteps = request.Workflow.Steps.Count;
            
            // Configurar tiempo de expiración
            if (request.CurrentStep.Timeout > TimeSpan.Zero)
            {
                request.ExpiresAt = DateTime.UtcNow.Add(request.CurrentStep.Timeout);
            }
            
            // Inicializar listas
            request.Approvals = new List<ApprovalDecision>();
            request.Denials = new List<ApprovalDecision>();
            request.Escalations = new List<ApprovalEscalation>();
            request.Comments = new List<ApprovalComment>();
            request.CurrentApprovers = new List<Approver>();
            
            await Task.CompletedTask;
        }
        
        private async Task<SelfApprovalResult> ProcessSelfApprovalAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            // Verificar si el solicitante puede auto-aprobar
            var canSelfApprove = await CanUserSelfApproveAsync(request, cancellationToken);
            
            if (canSelfApprove && request.SelfApprovalPolicy == SelfApprovalPolicy.AutoApprove)
            {
                // Auto-aprobar
                var approval = new ApprovalDecision
                {
                    DecisionId = GenerateDecisionId(),
                    RequestId = request.RequestId,
                    Decision = ApprovalDecisionType.Approve,
                    DecidedBy = request.RequestedBy,
                    Comments = "Auto-approved by requester",
                    DecidedAt = DateTime.UtcNow
                };
                
                request.Approvals.Add(approval);
                
                return new SelfApprovalResult
                {
                    Approved = true,
                    RequiresFurtherApproval = false
                };
            }
            else if (canSelfApprove && request.SelfApprovalPolicy == SelfApprovalPolicy.RequireConfirmation)
            {
                // Requerir confirmación del solicitante
                // En una implementación real, esto enviaría una notificación al solicitante
                return new SelfApprovalResult
                {
                    Approved = false,
                    RequiresFurtherApproval = true
                };
            }
            
            return new SelfApprovalResult
            {
                Approved = false,
                RequiresFurtherApproval = true
            };
        }
        
        private async Task DetermineCurrentApproversAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            var approvers = new List<Approver>();
            
            // Obtener aprobadores del paso actual
            foreach (var approverDef in request.CurrentStep.Approvers)
            {
                var users = await ResolveApproversAsync(approverDef, request, cancellationToken);
                approvers.AddRange(users);
            }
            
            // Si no hay aprobadores definidos, usar aprobadores por defecto
            if (approvers.Count == 0)
            {
                approvers = await GetDefaultApproversAsync(request, cancellationToken);
            }
            
            request.CurrentApprovers = approvers;
        }
        
        private async Task<List<Approver>> ResolveApproversAsync(
            ApproverDefinition definition,
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            var approvers = new List<Approver>();
            
            switch (definition.Type)
            {
                case ApproverType.User:
                    if (!string.IsNullOrEmpty(definition.UserId))
                    {
                        approvers.Add(new Approver
                        {
                            UserId = definition.UserId,
                            UserName = definition.UserName,
                            Type = ApproverType.User,
                            ResolvedAt = DateTime.UtcNow
                        });
                    }
                    break;
                    
                case ApproverType.Group:
                    if (!string.IsNullOrEmpty(definition.GroupId) && _userDirectory != null)
                    {
                        var groupMembers = await _userDirectory.GetGroupMembersAsync(
                            definition.GroupId, cancellationToken);
                        
                        foreach (var member in groupMembers)
                        {
                            approvers.Add(new Approver
                            {
                                UserId = member.UserId,
                                UserName = member.UserName,
                                Type = ApproverType.Group,
                                GroupId = definition.GroupId,
                                ResolvedAt = DateTime.UtcNow
                            });
                        }
                    }
                    break;
                    
                case ApproverType.Role:
                    if (!string.IsNullOrEmpty(definition.RoleName) && _userDirectory != null)
                    {
                        var roleUsers = await _userDirectory.GetUsersByRoleAsync(
                            definition.RoleName, cancellationToken);
                        
                        foreach (var user in roleUsers)
                        {
                            approvers.Add(new Approver
                            {
                                UserId = user.UserId,
                                UserName = user.UserName,
                                Type = ApproverType.Role,
                                RoleName = definition.RoleName,
                                ResolvedAt = DateTime.UtcNow
                            });
                        }
                    }
                    break;
                    
                case ApproverType.Dynamic:
                    // Resolver aprobadores dinámicos basados en el contexto
                    var dynamicApprovers = await ResolveDynamicApproversAsync(definition, request, cancellationToken);
                    approvers.AddRange(dynamicApprovers);
                    break;
            }
            
            return approvers;
        }
        
        private async Task<List<Approver>> ResolveDynamicApproversAsync(
            ApproverDefinition definition,
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            // Implementar lógica para aprobadores dinámicos
            // Por ejemplo: aprobadores basados en severidad, departamento, etc.
            
            var approvers = new List<Approver>();
            
            // Ejemplo: para alta severidad, incluir jefe de seguridad
            if (request.Context?.Severity >= 7)
            {
                approvers.Add(new Approver
                {
                    UserId = "security_chief",
                    UserName = "Security Chief",
                    Type = ApproverType.Dynamic,
                    Reason = "High severity incident",
                    ResolvedAt = DateTime.UtcNow
                });
            }
            
            return await Task.FromResult(approvers);
        }
        
        private async Task<List<Approver>> GetDefaultApproversAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            var approvers = new List<Approver>();
            
            // Obtener aprobadores por defecto del sistema
            // En una implementación real, esto vendría de configuración
            
            approvers.Add(new Approver
            {
                UserId = "admin",
                UserName = "System Administrator",
                Type = ApproverType.User,
                IsDefault = true,
                ResolvedAt = DateTime.UtcNow
            });
            
            return await Task.FromResult(approvers);
        }
        
        private async Task NotifyApproversAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            if (_notificationService == null)
                return;
            
            try
            {
                foreach (var approver in request.CurrentApprovers)
                {
                    await _notificationService.SendApprovalRequestAsync(
                        request,
                        approver,
                        cancellationToken);
                }
                
                _logger.LogDebug("Notificaciones enviadas a {Count} aprobadores para solicitud {RequestId}", 
                    request.CurrentApprovers.Count, request.RequestId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar notificaciones a aprobadores para solicitud {RequestId}", 
                    request.RequestId);
            }
        }
        
        private async Task NotifyRequesterAsync(
            ApprovalRequest request,
            bool approved,
            string reason,
            CancellationToken cancellationToken)
        {
            if (_notificationService == null)
                return;
            
            try
            {
                await _notificationService.SendApprovalResultAsync(
                    request,
                    approved,
                    reason,
                    cancellationToken);
                
                _logger.LogDebug("Notificación enviada al solicitante para solicitud {RequestId}", request.RequestId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar notificación al solicitante para solicitud {RequestId}", 
                    request.RequestId);
            }
        }
        
        private async Task<bool> CanUserApproveAsync(
            ApprovalRequest request,
            string userId,
            CancellationToken cancellationToken)
        {
            // Verificar si el usuario es aprobador actual
            if (request.CurrentApprovers.Any(a => a.UserId == userId))
            {
                return true;
            }
            
            // Verificar permisos adicionales
            if (_userDirectory != null)
            {
                var user = await _userDirectory.GetUserAsync(userId, cancellationToken);
                if (user != null && user.Roles.Contains("approval_admin"))
                {
                    return true;
                }
            }
            
            return false;
        }
        
        private async Task<bool> CanUserCancelAsync(
            ApprovalRequest request,
            string userId,
            CancellationToken cancellationToken)
        {
            // El solicitante puede cancelar
            if (request.RequestedBy == userId)
            {
                return true;
            }
            
            // Administradores pueden cancelar
            if (_userDirectory != null)
            {
                var user = await _userDirectory.GetUserAsync(userId, cancellationToken);
                if (user != null && user.Roles.Contains("approval_admin"))
                {
                    return true;
                }
            }
            
            return false;
        }
        
        private async Task<bool> CanUserSelfApproveAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            // Verificar política de auto-aprobación
            if (request.SelfApprovalPolicy == SelfApprovalPolicy.Disabled)
            {
                return false;
            }
            
            // Verificar si el solicitante tiene permisos de auto-aprobación
            if (_userDirectory != null)
            {
                var user = await _userDirectory.GetUserAsync(request.RequestedBy, cancellationToken);
                if (user != null && user.Roles.Contains("self_approver"))
                {
                    return true;
                }
            }
            
            return false;
        }
        
        private async Task<bool> CheckLevelCompletionAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            var currentStep = request.CurrentStep;
            var approvalsCount = request.Approvals.Count(a => 
                a.DecidedAt >= request.UpdatedAt.AddMinutes(-5)); // Aprobaciones recientes
            
            return approvalsCount >= currentStep.RequiredApprovals;
        }
        
        private async Task AdvanceToNextLevelOrCompleteAsync(
            ApprovalRequest request,
            bool approved,
            CancellationToken cancellationToken)
        {
            if (request.CurrentStepIndex < request.TotalSteps - 1)
            {
                // Avanzar al siguiente nivel
                await AdvanceToNextLevelAsync(request, cancellationToken);
            }
            else
            {
                // Completar solicitud
                await CompleteRequestAsync(request, approved, cancellationToken);
            }
        }
        
        private async Task AdvanceToNextLevelAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            request.CurrentStepIndex++;
            request.CurrentStep = request.Workflow.Steps[request.CurrentStepIndex];
            
            // Resetear aprobaciones para el nuevo nivel
            request.Approvals.Clear();
            
            // Determinar aprobadores para el nuevo nivel
            await DetermineCurrentApproversAsync(request, cancellationToken);
            
            // Configurar nueva expiración
            if (request.CurrentStep.Timeout > TimeSpan.Zero)
            {
                request.ExpiresAt = DateTime.UtcNow.Add(request.CurrentStep.Timeout);
            }
            
            // Cancelar timer anterior y configurar nuevo
            CancelExpirationTimer(request.RequestId);
            SetupExpirationTimer(request);
            
            // Guardar cambios
            await SaveRequestAsync(request, cancellationToken);
            
            // Notificar a nuevos aprobadores
            await NotifyApproversAsync(request, cancellationToken);
            
            _logger.LogInformation("Solicitud avanzada al nivel {Level}: {RequestId}", 
                request.CurrentStepIndex, request.RequestId);
        }
        
        private async Task CompleteRequestAsync(
            ApprovalRequest request,
            bool approved,
            CancellationToken cancellationToken)
        {
            request.Status = approved ? ApprovalStatus.Approved : ApprovalStatus.Denied;
            request.CompletedAt = DateTime.UtcNow;
            request.UpdatedAt = DateTime.UtcNow;
            
            // Cancelar timer de expiración
            CancelExpirationTimer(request.RequestId);
            
            // Remover de solicitudes activas
            _activeRequests.TryRemove(request.RequestId, out _);
            
            // Guardar cambios
            await SaveRequestAsync(request, cancellationToken);
            
            // Notificar al solicitante
            await NotifyRequesterAsync(
                request, 
                approved, 
                approved ? "Request approved" : "Request denied", 
                cancellationToken);
            
            // Notificar a listeners
            await NotifyListenersAsync(request, approved, cancellationToken);
            
            _logger.LogInformation("Solicitud completada: {RequestId}, Status: {Status}", 
                request.RequestId, request.Status);
        }
        
        private async Task UpdateCurrentApproversAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            // Remover aprobadores que ya aprobaron
            var approvedUserIds = request.Approvals
                .Select(a => a.DecidedBy)
                .Distinct()
                .ToList();
            
            request.CurrentApprovers = request.CurrentApprovers
                .Where(a => !approvedUserIds.Contains(a.UserId))
                .ToList();
            
            // Guardar cambios
            await SaveRequestAsync(request, cancellationToken);
        }
        
        private async Task SaveRequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                await _repository.SaveRequestAsync(request, cancellationToken);
            }
        }
        
        private async Task FinalizeRequestAsync(
            ApprovalRequest request,
            CancellationToken cancellationToken)
        {
            // Guardar en repositorio
            await SaveRequestAsync(request, cancellationToken);
            
            // Notificar al solicitante
            await NotifyRequesterAsync(
                request,
                request.Status == ApprovalStatus.Approved,
                request.Status == ApprovalStatus.Approved ? "Auto-approved" : "Auto-denied",
                cancellationToken);
        }
        
        private async Task NotifyApproversOfCancellationAsync(
            ApprovalRequest request,
            string cancelledBy,
            string reason,
            CancellationToken cancellationToken)
        {
            if (_notificationService == null)
                return;
            
            try
            {
                foreach (var approver in request.CurrentApprovers)
                {
                    await _notificationService.SendCancellationNotificationAsync(
                        request,
                        approver,
                        cancelledBy,
                        reason,
                        cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar notificaciones de cancelación para solicitud {RequestId}", 
                    request.RequestId);
            }
        }
        
        private async Task SendReminderToApproversAsync(
            ApprovalRequest request,
            string sentBy,
            CancellationToken cancellationToken)
        {
            if (_notificationService == null)
                return;
            
            try
            {
                foreach (var approver in request.CurrentApprovers)
                {
                    await _notificationService.SendReminderAsync(
                        request,
                        approver,
                        sentBy,
                        cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar recordatorios para solicitud {RequestId}", request.RequestId);
            }
        }
        
        private async Task NotifyListenersAsync(
            ApprovalRequest request,
            bool approved,
            CancellationToken cancellationToken)
        {
            if (_listeners.TryGetValue(request.RequestId, out var listeners))
            {
                foreach (var listener in listeners)
                {
                    try
                    {
                        await listener.OnApprovalCompletedAsync(request, approved, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error al notificar listener para solicitud {RequestId}", request.RequestId);
                    }
                }
            }
        }
        
        private async Task<int> GetTotalRequestCountAsync(CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                return await _repository.GetTotalRequestCountAsync(cancellationToken);
            }
            
            return _activeRequests.Count;
        }
        
        private async Task<TimeSpan> GetAverageApprovalTimeAsync(CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                return await _repository.GetAverageApprovalTimeAsync(cancellationToken);
            }
            
            return TimeSpan.Zero;
        }
        
        private async Task<double> GetApprovalRateAsync(CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                return await _repository.GetApprovalRateAsync(cancellationToken);
            }
            
            return 0.0;
        }
        
        private async Task<int> GetTotalEscalationsAsync(CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                return await _repository.GetTotalEscalationsAsync(cancellationToken);
            }
            
            return _activeRequests.Values.Sum(r => r.Escalations.Count);
        }
        
        private async Task<int> GetTotalCommentsAsync(CancellationToken cancellationToken)
        {
            if (_repository != null)
            {
                return await _repository.GetTotalCommentsAsync(cancellationToken);
            }
            
            return _activeRequests.Values.Sum(r => r.Comments.Count);
        }
        
        private TimeSpan GetEngineUptime()
        {
            // Implementar cálculo de uptime real
            return TimeSpan.FromMinutes(0);
        }
        
        private string GenerateRequestId()
        {
            return $"APR-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateDecisionId()
        {
            return $"DEC-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateEscalationId()
        {
            return $"ESC-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateCommentId()
        {
            return $"CMT-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateListenerId()
        {
            return $"LST-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private string GenerateWorkflowId()
        {
            return $"WRK-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant();
        }
        
        private void OnApprovalGranted(ApprovalGrantedEventArgs e)
        {
            ApprovalGranted?.Invoke(this, e);
        }
        
        private void OnApprovalDenied(ApprovalDeniedEventArgs e)
        {
            ApprovalDenied?.Invoke(this, e);
        }
        
        private void OnApprovalEscalated(ApprovalEscalatedEventArgs e)
        {
            ApprovalEscalated?.Invoke(this, e);
        }
        
        private void OnApprovalExpired(ApprovalExpiredEventArgs e)
        {
            ApprovalExpired?.Invoke(this, e);
        }
        
        private void OnApprovalReminder(ApprovalReminderEventArgs e)
        {
            ApprovalReminder?.Invoke(this, e);
        }
        
        private void ValidateInitialized()
        {
            if (!_isInitialized)
            {
                throw new InvalidOperationException(
                    "ApprovalEngine no está inicializado. Llame a InitializeAsync primero.");
            }
        }
        
        #endregion
    }
    
    #region Clases de Soporte
    
    public class ApprovalRequest
    {
        public string RequestId { get; set; }
        public string PlaybookId { get; set; }
        public string PlaybookName { get; set; }
        public string ExecutionId { get; set; }
        
        public PlaybookExecutionContext Context { get; set; }
        public ApprovalWorkflow Workflow { get; set; }
        
        public string RequestedBy { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        
        public ApprovalStatus Status { get; set; }
        public ApprovalPriority Priority { get; set; }
        
        // Workflow tracking
        public int CurrentStepIndex { get; set; }
        public int TotalSteps { get; set; }
        public ApprovalWorkflowStep CurrentStep { get; set; }
        public List<Approver> CurrentApprovers { get; set; }
        
        // Decisions
        public List<ApprovalDecision> Approvals { get; set; }
        public List<ApprovalDecision> Denials { get; set; }
        public List<ApprovalEscalation> Escalations { get; set; }
        public List<ApprovalComment> Comments { get; set; }
        
        // Metadata
        public DateTime? ExpiresAt { get; set; }
        public string ExpirationReason { get; set; }
        public string DenialReason { get; set; }
        public string CancelledBy { get; set; }
        public string CancellationReason { get; set; }
        public string AutoApprovalReason { get; set; }
        
        // Reminders
        public int ReminderCount { get; set; }
        public DateTime? LastReminderAt { get; set; }
        
        // Self-approval
        public bool RequiresSelfApproval { get; set; }
        public SelfApprovalPolicy SelfApprovalPolicy { get; set; }
        
        public ApprovalRequest()
        {
            Approvals = new List<ApprovalDecision>();
            Denials = new List<ApprovalDecision>();
            Escalations = new List<ApprovalEscalation>();
            Comments = new List<ApprovalComment>();
            CurrentApprovers = new List<Approver>();
            Status = ApprovalStatus.Pending;
            Priority = ApprovalPriority.Medium;
            SelfApprovalPolicy = SelfApprovalPolicy.Disabled;
        }
    }
    
    public class ApprovalWorkflow
    {
        public string WorkflowId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<ApprovalWorkflowStep> Steps { get; set; }
        public Dictionary<string, object> Metadata { get; set; }
        
        public ApprovalWorkflow()
        {
            Steps = new List<ApprovalWorkflowStep>();
            Metadata = new Dictionary<string, object>();
        }
    }
    
    public class ApprovalWorkflowStep
    {
        public int StepIndex { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<ApproverDefinition> Approvers { get; set; }
        public int RequiredApprovals { get; set; }
        public TimeSpan Timeout { get; set; }
        public bool CanEscalate { get; set; }
        public TimeSpan EscalationTimeout { get; set; }
        public Dictionary<string, object> Conditions { get; set; }
        
        public ApprovalWorkflowStep()
        {
            Approvers = new List<ApproverDefinition>();
            Conditions = new Dictionary<string, object>();
            RequiredApprovals = 1;
            Timeout = TimeSpan.FromHours(24);
            EscalationTimeout = TimeSpan.FromHours(12);
        }
    }
    
    public class ApproverDefinition
    {
        public ApproverType Type { get; set; }
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string GroupId { get; set; }
        public string GroupName { get; set; }
        public string RoleName { get; set; }
        public string DynamicRule { get; set; }
        public int Order { get; set; }
        
        public ApproverDefinition()
        {
            Type = ApproverType.User;
            Order = 0;
        }
    }
    
    public class Approver
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public ApproverType Type { get; set; }
        public string GroupId { get; set; }
        public string RoleName { get; set; }
        public string Reason { get; set; }
        public bool IsDefault { get; set; }
        public DateTime ResolvedAt { get; set; }
    }
    
    public class ApprovalDecision
    {
        public string DecisionId { get; set; }
        public string RequestId { get; set; }
        public ApprovalDecisionType Decision { get; set; }
        public string DecidedBy { get; set; }
        public string Comments { get; set; }
        public DateTime DecidedAt { get; set; }
    }
    
    public class ApprovalEscalation
    {
        public string EscalationId { get; set; }
        public string RequestId { get; set; }
        public string EscalatedBy { get; set; }
        public string Reason { get; set; }
        public DateTime EscalatedAt { get; set; }
        public int PreviousLevel { get; set; }
        public int NewLevel { get; set; }
    }
    
    public class ApprovalComment
    {
        public string CommentId { get; set; }
        public string RequestId { get; set; }
        public string UserId { get; set; }
        public string Comment { get; set; }
        public DateTime CreatedAt { get; set; }
    }
    
    public class ApprovalListResult
    {
        public ApprovalListQuery Query { get; set; }
        public int TotalCount { get; set; }
        public List<ApprovalRequest> Requests { get; set; }
        
        public ApprovalListResult()
        {
            Requests = new List<ApprovalRequest>();
        }
    }
    
    public class ApprovalListQuery
    {
        public string RequestedBy { get; set; }
        public ApprovalStatus? Status { get; set; }
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }
        public string PlaybookId { get; set; }
        public int PageIndex { get; set; }
        public int PageSize { get; set; }
        public SortOrder SortOrder { get; set; }
        
        public ApprovalListQuery()
        {
            PageIndex = 0;
            PageSize = 20;
            SortOrder = SortOrder.Descending;
        }
    }
    
    public class ApprovalEngineStats
    {
        public DateTime Timestamp { get; set; }
        public int TotalRequests { get; set; }
        public int ActiveRequests { get; set; }
        public int PendingRequests { get; set; }
        public TimeSpan AverageApprovalTime { get; set; }
        public double ApprovalRate { get; set; }
        public int TotalEscalations { get; set; }
        public int TotalComments { get; set; }
        public bool IsInitialized { get; set; }
        public TimeSpan Uptime { get; set; }
    }
    
    public enum ApprovalStatus
    {
        Pending,
        Approved,
        Denied,
        Cancelled,
        Expired,
        AutoApproved
    }
    
    public enum ApprovalPriority
    {
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4,
        None = 0
    }
    
    public enum ApproverType
    {
        User,
        Group,
        Role,
        Dynamic
    }
    
    public enum ApprovalDecisionType
    {
        Approve,
        Deny
    }
    
    public enum SelfApprovalPolicy
    {
        Disabled,
        AutoApprove,
        RequireConfirmation
    }
    
    public enum SortOrder
    {
        Ascending,
        Descending
    }
    
    #endregion
}