using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace BWP.Enterprise.Cloud.Api
{
    public class TenantMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<TenantMiddleware> _logger;
        private readonly ITenantRepository _tenantRepository;
        private readonly IJwtValidator _jwtValidator;
        
        public TenantMiddleware(
            RequestDelegate next,
            ILogger<TenantMiddleware> logger,
            ITenantRepository tenantRepository,
            IJwtValidator jwtValidator)
        {
            _next = next;
            _logger = logger;
            _tenantRepository = tenantRepository;
            _jwtValidator = jwtValidator;
        }
        
        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            try
            {
                // Extract tenant ID from request
                var tenantId = ExtractTenantId(context);
                
                if (string.IsNullOrEmpty(tenantId))
                {
                    await WriteErrorResponse(context, 400, "Missing tenant identifier");
                    return;
                }
                
                // Validate tenant exists and is active
                var tenant = await _tenantRepository.GetTenantAsync(tenantId);
                if (tenant == null)
                {
                    await WriteErrorResponse(context, 404, $"Tenant not found: {tenantId}");
                    return;
                }
                
                if (!tenant.IsActive)
                {
                    await WriteErrorResponse(context, 403, $"Tenant is inactive: {tenantId}");
                    return;
                }
                
                // Validate JWT token
                var authResult = await ValidateAuthenticationAsync(context, tenant);
                if (!authResult.IsValid)
                {
                    await WriteErrorResponse(context, 401, $"Authentication failed: {authResult.Error}");
                    return;
                }
                
                // Check rate limiting
                if (!await CheckRateLimitAsync(context, tenant))
                {
                    await WriteErrorResponse(context, 429, "Rate limit exceeded");
                    return;
                }
                
                // Set tenant context for downstream handlers
                context.Items["Tenant"] = tenant;
                context.Items["User"] = authResult.User;
                context.Items["RequestId"] = Guid.NewGuid().ToString();
                
                // Add security headers
                AddSecurityHeaders(context, tenant);
                
                // Log request
                LogRequest(context, tenantId, authResult.User?.Id);
                
                await _next(context);
                
                // Log response
                LogResponse(context, tenantId, stopwatch.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Tenant middleware error");
                await WriteErrorResponse(context, 500, "Internal server error");
            }
        }
        
        private string ExtractTenantId(HttpContext context)
        {
            // Try to extract from various sources in order of priority
            
            // 1. From JWT token
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring(7);
                var tenantId = _jwtValidator.ExtractTenantId(token);
                if (!string.IsNullOrEmpty(tenantId))
                {
                    return tenantId;
                }
            }
            
            // 2. From custom header
            var customHeader = context.Request.Headers["X-Tenant-ID"].FirstOrDefault();
            if (!string.IsNullOrEmpty(customHeader))
            {
                return customHeader;
            }
            
            // 3. From subdomain
            var host = context.Request.Host.Host;
            if (host.Contains('.'))
            {
                var subdomain = host.Split('.')[0];
                if (subdomain != "www" && subdomain != "api")
                {
                    return subdomain;
                }
            }
            
            // 4. From query string (for development only)
            var queryTenant = context.Request.Query["tenant"].FirstOrDefault();
            if (!string.IsNullOrEmpty(queryTenant) && context.Request.Host.Host.Contains("localhost"))
            {
                return queryTenant;
            }
            
            return null;
        }
        
        private async Task<AuthValidationResult> ValidateAuthenticationAsync(HttpContext context, Tenant tenant)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            
            if (string.IsNullOrEmpty(authHeader))
            {
                return AuthValidationResult.Failed("Missing authorization header");
            }
            
            if (authHeader.StartsWith("Bearer "))
            {
                return await ValidateJwtTokenAsync(authHeader.Substring(7), tenant);
            }
            else if (authHeader.StartsWith("ApiKey "))
            {
                return await ValidateApiKeyAsync(authHeader.Substring(7), tenant);
            }
            
            return AuthValidationResult.Failed("Unsupported authentication scheme");
        }
        
        private async Task<AuthValidationResult> ValidateJwtTokenAsync(string token, Tenant tenant)
        {
            try
            {
                var validationResult = await _jwtValidator.ValidateTokenAsync(token, tenant);
                
                if (!validationResult.IsValid)
                {
                    _logger.LogWarning($"JWT validation failed for tenant {tenant.Id}: {validationResult.Error}");
                    return AuthValidationResult.Failed(validationResult.Error);
                }
                
                // Check if user has access to this endpoint
                var endpoint = context.Request.Path;
                if (!await _tenantRepository.HasPermissionAsync(validationResult.User.Id, endpoint))
                {
                    return AuthValidationResult.Failed("Insufficient permissions");
                }
                
                return AuthValidationResult.Success(validationResult.User);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"JWT validation error for tenant {tenant.Id}");
                return AuthValidationResult.Failed("Token validation error");
            }
        }
        
        private async Task<AuthValidationResult> ValidateApiKeyAsync(string apiKey, Tenant tenant)
        {
            try
            {
                // Find API key in database
                var keyRecord = await _tenantRepository.GetApiKeyAsync(apiKey);
                
                if (keyRecord == null)
                {
                    return AuthValidationResult.Failed("Invalid API key");
                }
                
                if (keyRecord.TenantId != tenant.Id)
                {
                    return AuthValidationResult.Failed("API key does not belong to this tenant");
                }
                
                if (!keyRecord.IsActive)
                {
                    return AuthValidationResult.Failed("API key is inactive");
                }
                
                if (keyRecord.ExpiresAt.HasValue && keyRecord.ExpiresAt.Value < DateTime.UtcNow)
                {
                    return AuthValidationResult.Failed("API key has expired");
                }
                
                // Check rate limiting for API key
                if (keyRecord.RequestsToday >= keyRecord.DailyLimit)
                {
                    return AuthValidationResult.Failed("Daily request limit exceeded");
                }
                
                // Update request count
                await _tenantRepository.IncrementApiKeyUsageAsync(apiKey);
                
                // Get user associated with API key
                var user = await _tenantRepository.GetUserAsync(keyRecord.UserId);
                
                return AuthValidationResult.Success(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"API key validation error for tenant {tenant.Id}");
                return AuthValidationResult.Failed("API key validation error");
            }
        }
        
        private async Task<bool> CheckRateLimitAsync(HttpContext context, Tenant tenant)
        {
            var clientIp = GetClientIp(context);
            var endpoint = context.Request.Path;
            
            var rateLimitKey = $"rate_limit:{tenant.Id}:{clientIp}:{endpoint}";
            
            // Check if IP is whitelisted
            if (tenant.WhitelistedIps.Contains(clientIp))
            {
                return true;
            }
            
            // Check if IP is blacklisted
            if (tenant.BlacklistedIps.Contains(clientIp))
            {
                _logger.LogWarning($"Blacklisted IP attempted access: {clientIp}");
                return false;
            }
            
            // Get rate limit configuration for this endpoint
            var rateLimit = tenant.GetRateLimitForEndpoint(endpoint);
            
            // Check current rate
            var currentRate = await _tenantRepository.GetCurrentRateAsync(rateLimitKey);
            
            if (currentRate >= rateLimit.RequestsPerMinute)
            {
                // Log rate limit violation
                await _tenantRepository.LogRateLimitViolationAsync(
                    tenant.Id,
                    clientIp,
                    endpoint,
                    currentRate
                );
                
                // Add IP to watchlist if multiple violations
                var violations = await _tenantRepository.GetRateLimitViolationsAsync(clientIp, TimeSpan.FromHours(1));
                if (violations >= 5)
                {
                    await _tenantRepository.AddToBlacklistAsync(tenant.Id, clientIp, "Rate limit violations");
                }
                
                return false;
            }
            
            // Increment rate counter
            await _tenantRepository.IncrementRateAsync(rateLimitKey, rateLimit.WindowMinutes);
            
            return true;
        }
        
        private void AddSecurityHeaders(HttpContext context, Tenant tenant)
        {
            var headers = context.Response.Headers;
            
            // Security headers
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["X-XSS-Protection"] = "1; mode=block";
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
            
            // CSP based on tenant configuration
            if (!string.IsNullOrEmpty(tenant.ContentSecurityPolicy))
            {
                headers["Content-Security-Policy"] = tenant.ContentSecurityPolicy;
            }
            
            // Tenant-specific headers
            headers["X-Tenant-ID"] = tenant.Id;
            headers["X-Tenant-Name"] = tenant.Name;
            
            // Request tracing
            if (context.Items.TryGetValue("RequestId", out var requestId))
            {
                headers["X-Request-ID"] = requestId.ToString();
            }
        }
        
        private string GetClientIp(HttpContext context)
        {
            // Check for forwarded headers (behind proxy)
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                return forwardedFor.Split(',')[0].Trim();
            }
            
            // Check for real IP header
            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                return realIp;
            }
            
            return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }
        
        private void LogRequest(HttpContext context, string tenantId, string userId)
        {
            var logEntry = new RequestLog
            {
                Id = Guid.NewGuid().ToString(),
                TenantId = tenantId,
                UserId = userId,
                Timestamp = DateTime.UtcNow,
                Method = context.Request.Method,
                Path = context.Request.Path,
                QueryString = context.Request.QueryString.ToString(),
                ClientIp = GetClientIp(context),
                UserAgent = context.Request.Headers["User-Agent"].FirstOrDefault(),
                ContentLength = context.Request.ContentLength ?? 0,
                Headers = context.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
            };
            
            // Don't log sensitive headers
            logEntry.Headers.Remove("Authorization");
            logEntry.Headers.Remove("Cookie");
            
            _logger.LogInformation("Request: {@LogEntry}", logEntry);
            
            // Store in database asynchronously
            _ = _tenantRepository.LogRequestAsync(logEntry);
        }
        
        private void LogResponse(HttpContext context, string tenantId, long durationMs)
        {
            var logEntry = new ResponseLog
            {
                Id = context.Items["RequestId"]?.ToString() ?? Guid.NewGuid().ToString(),
                TenantId = tenantId,
                Timestamp = DateTime.UtcNow,
                StatusCode = context.Response.StatusCode,
                DurationMs = durationMs,
                ContentLength = context.Response.ContentLength ?? 0,
                Headers = context.Response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
            };
            
            _logger.LogInformation("Response: {@LogEntry}", logEntry);
            
            // Store in database asynchronously
            _ = _tenantRepository.LogResponseAsync(logEntry);
        }
        
        private async Task WriteErrorResponse(HttpContext context, int statusCode, string message)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json";
            
            var errorResponse = new
            {
                error = new
                {
                    code = statusCode,
                    message = message,
                    timestamp = DateTime.UtcNow,
                    requestId = context.Items["RequestId"]?.ToString() ?? Guid.NewGuid().ToString()
                }
            };
            
            var json = JsonConvert.SerializeObject(errorResponse);
            await context.Response.WriteAsync(json);
        }
    }
    
    public class AuthValidationResult
    {
        public bool IsValid { get; set; }
        public User User { get; set; }
        public string Error { get; set; }
        
        public static AuthValidationResult Success(User user)
        {
            return new AuthValidationResult
            {
                IsValid = true,
                User = user
            };
        }
        
        public static AuthValidationResult Failed(string error)
        {
            return new AuthValidationResult
            {
                IsValid = false,
                Error = error
            };
        }
    }
    
    public class Tenant
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public string ContentSecurityPolicy { get; set; }
        public List<string> WhitelistedIps { get; set; } = new List<string>();
        public List<string> BlacklistedIps { get; set; } = new List<string>();
        public Dictionary<string, RateLimit> RateLimits { get; set; } = new Dictionary<string, RateLimit>();
        public TenantPlan Plan { get; set; }
        
        public RateLimit GetRateLimitForEndpoint(string endpoint)
        {
            // Find specific rate limit for endpoint
            if (RateLimits.TryGetValue(endpoint, out var specificLimit))
            {
                return specificLimit;
            }
            
            // Find pattern match
            foreach (var kvp in RateLimits)
            {
                if (endpoint.StartsWith(kvp.Key))
                {
                    return kvp.Value;
                }
            }
            
            // Return default based on plan
            return Plan switch
            {
                TenantPlan.Free => new RateLimit { RequestsPerMinute = 60, WindowMinutes = 1 },
                TenantPlan.Pro => new RateLimit { RequestsPerMinute = 300, WindowMinutes = 1 },
                TenantPlan.Enterprise => new RateLimit { RequestsPerMinute = 1000, WindowMinutes = 1 },
                _ => new RateLimit { RequestsPerMinute = 60, WindowMinutes = 1 }
            };
        }
    }
    
    public enum TenantPlan
    {
        Free,
        Pro,
        Enterprise
    }
    
    public class RateLimit
    {
        public int RequestsPerMinute { get; set; }
        public int WindowMinutes { get; set; }
    }
    
    public class User
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public bool IsActive { get; set; }
        public DateTime LastLogin { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }
    
    public class RequestLog
    {
        public string Id { get; set; }
        public string TenantId { get; set; }
        public string UserId { get; set; }
        public DateTime Timestamp { get; set; }
        public string Method { get; set; }
        public string Path { get; set; }
        public string QueryString { get; set; }
        public string ClientIp { get; set; }
        public string UserAgent { get; set; }
        public long ContentLength { get; set; }
        public Dictionary<string, string> Headers { get; set; }
    }
    
    public class ResponseLog
    {
        public string Id { get; set; }
        public string TenantId { get; set; }
        public DateTime Timestamp { get; set; }
        public int StatusCode { get; set; }
        public long DurationMs { get; set; }
        public long ContentLength { get; set; }
        public Dictionary<string, string> Headers { get; set; }
    }
    
    public interface ITenantRepository
    {
        Task<Tenant> GetTenantAsync(string tenantId);
        Task<User> GetUserAsync(string userId);
        Task<ApiKey> GetApiKeyAsync(string apiKey);
        Task<bool> HasPermissionAsync(string userId, string endpoint);
        Task IncrementApiKeyUsageAsync(string apiKey);
        Task<int> GetCurrentRateAsync(string rateLimitKey);
        Task IncrementRateAsync(string rateLimitKey, int windowMinutes);
        Task LogRateLimitViolationAsync(string tenantId, string clientIp, string endpoint, int currentRate);
        Task<int> GetRateLimitViolationsAsync(string clientIp, TimeSpan timeWindow);
        Task AddToBlacklistAsync(string tenantId, string clientIp, string reason);
        Task LogRequestAsync(RequestLog log);
        Task LogResponseAsync(ResponseLog log);
    }
    
    public interface IJwtValidator
    {
        Task<JwtValidationResult> ValidateTokenAsync(string token, Tenant tenant);
        string ExtractTenantId(string token);
    }
    
    public class JwtValidationResult
    {
        public bool IsValid { get; set; }
        public User User { get; set; }
        public string Error { get; set; }
        public Dictionary<string, object> Claims { get; set; }
    }
    
    public class ApiKey
    {
        public string Key { get; set; }
        public string TenantId { get; set; }
        public string UserId { get; set; }
        public string Name { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public int DailyLimit { get; set; }
        public int RequestsToday { get; set; }
        public List<string> Permissions { get; set; } = new List<string>();
        public DateTime LastUsed { get; set; }
    }
}