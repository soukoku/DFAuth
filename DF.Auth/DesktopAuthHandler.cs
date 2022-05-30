using IdentityModel;
using IdentityModel.OidcClient;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DF.Auth
{
    /// <summary>
    /// Handles DF login for a desktop app. Must be used as a singleton.
    /// </summary>
    public class DesktopAuthHandler : IDisposable
    {
        readonly ConcurrentDictionary<string, AuthorizeState> _pendingStates
            = new ConcurrentDictionary<string, AuthorizeState>();
        readonly ConcurrentDictionary<string, OidcClient> _knownClients
            = new ConcurrentDictionary<string, OidcClient>();
        readonly string _redirectUrl;
        readonly HttpListener _host;
        private bool _disposed;

        /// <summary>
        /// TODO: to be used.
        /// </summary>
        public bool AllowUnsolicited { get; set; }

        /// <summary>
        /// Event raised when a login result becomes available. This can happen on a different thread.
        /// </summary>
        public event EventHandler<LoginResult>? LoginCompleted;

        /// <summary>
        /// Constructor. The parameters needs to match the registered redirect uri in DF.
        /// The server host is always localhost.
        /// </summary>
        /// <param name="handlerPath">Path of the redirect url, starts with '/'</param>
        /// <param name="localPort">Port of the local http listener.</param>
        public DesktopAuthHandler(string handlerPath = "/signin-oidc", int localPort = 18989)
        {
            _redirectUrl = $"http://localhost:{localPort}{handlerPath}";
            _host = new HttpListener();
            _host.Prefixes.Add(_redirectUrl);

            _host.Start();
            Task.Run(async () =>
            {
                while (_host.IsListening)
                {
                    try
                    {
                        var ctx = await _host.GetContextAsync();
                        await HandleHttpRequest(ctx);
                    }
                    catch { }
                }
            });
        }

        /// <summary>
        /// Starts an interactive user login.
        /// </summary>
        /// <param name="server">The host name of the DF /authen site.</param>
        /// <param name="clientId">The registered app id in DF.</param>
        /// <param name="scope">Scopes to be requested.</param>
        /// <param name="initialClient">Optional initial client code.</param>
        /// <param name="initialAccount">Optional initial user account (email).</param>
        /// <param name="alwaysPrompt">Optional flag to always show login prompt.</param>
        /// <returns></returns>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task InteractiveLoginAsync(string server,
            string clientId,
            string scope = "openid profile roles df_api df_legacy_api offline_access",
            string initialClient = "", string initialAccount = "", bool alwaysPrompt = false)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DesktopAuthHandler));

            var oidcKey = $"{server}-{clientId}-{scope}";
            var oidc = _knownClients.GetOrAdd(oidcKey, _ =>
            {
                var options = new OidcClientOptions
                {
                    Authority = $"https://{server}/authen/identity/",
                    ClientId = clientId,
                    RedirectUri = _redirectUrl,
                    Scope = scope,
                };

                return new OidcClient(options);
            });

            var extra = new IdentityModel.Client.Parameters();
            if (!string.IsNullOrEmpty(initialClient))
            {
                extra.Add("acr_values", $"tenant:{initialClient}");
            }
            extra.AddOptional("login_hint", initialAccount);
            if (alwaysPrompt)
            {
                extra.Add("prompt", "login");
            }

            var state = await oidc.PrepareLoginAsync(extra);

            _pendingStates.AddOrUpdate(state.State, state, (key, exist) =>
            {
                // should never happen
                return state;
            });
            OpenBrowser(state.StartUrl);
        }

        static void OpenBrowser(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }


        private async Task HandleHttpRequest(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod == "GET")
            {
                await HandleLoginResponseAsync(ctx.Request.Url?.Query, ctx);
            }
            else if (ctx.Request.HttpMethod == "POST")
            {
                if (!string.Equals(ctx.Request.ContentType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    RespondWithError(ctx, HttpStatusCode.UnsupportedMediaType, "bad_request", $"{ctx.Request.ContentType} content is not supported.");
                }
                else if (ctx.Request.HasEntityBody)
                {
                    using (var sr = new StreamReader(ctx.Request.InputStream, Encoding.UTF8))
                    {
                        var body = await sr.ReadToEndAsync();
                        await HandleLoginResponseAsync(body, ctx);
                    }
                }
                else
                {
                    RespondWithError(ctx, HttpStatusCode.BadRequest, "bad_request", "No data received.");
                }
            }
            else
            {
                RespondWithError(ctx, HttpStatusCode.MethodNotAllowed, "bad_request", $"{ctx.Request.HttpMethod} method is not supported.");
            }
        }

        /// <summary>
        /// Attempt to handle login response received through non-http means.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public void HandleLoginResponse(string value)
        {
            _ = HandleLoginResponseAsync(value, null);
        }

        private async Task HandleLoginResponseAsync(string? value, HttpListenerContext? ctx)
        {
            if (string.IsNullOrEmpty(value))
            {
                RespondWithError(ctx, HttpStatusCode.BadRequest, "bad_request", "No data received.");
            }
            var resp = new IdentityModel.Client.AuthorizeResponse(value);
            if (resp.IsError)
            {
                RespondWithError(ctx, HttpStatusCode.BadRequest, resp.Error, resp.ErrorDescription);
            }
            if (_pendingStates.TryGetValue(resp.State, out AuthorizeState? authState))
            {
                var nonValidatedId = await new NoValidationIdentityTokenValidator().ValidateAsync(resp.IdentityToken, null);
                var clientId = nonValidatedId.User.Claims.FirstOrDefault(c => c.Type == IdentityModel.JwtClaimTypes.Audience)?.Value;
                var issuer = nonValidatedId.User.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Issuer)?.Value;
                if (issuer != null && clientId != null)
                {
                    var server = new Uri(issuer).Host;
                    var oidcKey = $"{server}-{clientId}-{resp.Scope}";
                    if (_knownClients.TryGetValue(oidcKey, out var oidc))
                    {
                        var result = await oidc.ProcessResponseAsync(value, authState);
                        if (result.IsError)
                        {
                            RespondWithError(ctx, HttpStatusCode.BadRequest, result.Error, result.ErrorDescription);
                        }
                        else
                        {
                            RespondWithSuccess(ctx, result);
                        }
                    }
                }
            }
            else if (AllowUnsolicited)
            {
                // TODO: unsolicited is insecure but it's what people want.
            }
            RespondWithError(ctx, HttpStatusCode.BadRequest, "invalid_request", "This auth response cannot be verified.");
        }

        private void RespondWithSuccess(HttpListenerContext? ctx, LoginResult result)
        {
            if (ctx != null)
            {
                try
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                    ctx.Response.Headers["ContentType"] = "text/html";
                    using (var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8))
                    {
                        writer.Write("Success. You can close this window now.");
                        writer.Flush();
                    }
                }
                catch { }
            }
            try
            {
                LoginCompleted?.Invoke(this, result);
            }
            catch { }
        }

        private void RespondWithError(HttpListenerContext? ctx, HttpStatusCode httpCode, string errorCode, string errorDescription)
        {
            if (ctx != null)
            {
                try
                {
                    ctx.Response.StatusCode = (int)httpCode;
                    ctx.Response.Headers["ContentType"] = "text/html";
                    using (var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8))
                    {
                        writer.Write($"Error ({errorCode}). {errorDescription}");
                        writer.Flush();
                    }
                }
                catch { }
            }
            try
            {
                LoginCompleted?.Invoke(this, new LoginResult(errorCode, errorDescription));
            }
            catch { }
        }

        /// <summary>
        /// Cleanup this handler.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_host.IsListening) _host.Stop();
                }
                _disposed = true;
            }
        }

        /// <summary>
        /// Cleanup this handler.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}