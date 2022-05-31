using IdentityModel.OidcClient;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
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
        readonly string _redirectUrl;
        readonly HttpListener _host;
        readonly string _saasServer;
        readonly string _clientId;
        readonly string _scope;
        readonly OidcClient _oidc;
        bool _disposed;

        /// <summary>
        /// When <code>true</code> allows accepting responses not initiated from this handler.
        /// This is insecure and should only be used for testing.
        /// </summary>
        public bool AllowUnsolicited { get; set; }

        /// <summary>
        /// Event raised when a login result becomes available. This can happen on a different thread.
        /// </summary>
        public event EventHandler<LoginResult>? LoginCompleted;

        /// <summary>
        /// Gets the html template.
        /// </summary>
        public HtmlTemplate HtmlTemplate { get; } = new HtmlTemplate();

        /// <summary>
        /// Gets an access token refresher for tokens received through this handler.
        /// </summary>
        /// <returns></returns>
        public AccessTokenRefresher GetTokenRefresher() => new AccessTokenRefresher(_oidc);

        /// <summary>
        /// Constructor. The parameters needs to match the registered redirect uri in DF.
        /// The server host is always localhost.
        /// </summary>
        /// <param name="server">The host name of the DF /authen site.</param>
        /// <param name="clientId">The registered app id in DF.</param>
        /// <param name="clientSecret">Secret value of the registered app.</param>
        /// <param name="scope">Scopes to be requested.</param>
        /// <param name="handlerPath">Path of the redirect url, starts with '/'</param>
        /// <param name="localPort">Port of the local http listener.</param>
        public DesktopAuthHandler(string server,
            string clientId,
            string clientSecret,
            string scope = "openid profile roles df_api df_legacy_api offline_access",
            string handlerPath = "/signin-oidc/", int localPort = 18989)
        {
            _saasServer = server;
            _clientId = clientId;
            _scope = scope;
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

            var options = new OidcClientOptions
            {
                Authority = $"https://{_saasServer}/authen/identity/",
                ClientId = _clientId,
                ClientSecret = clientSecret,
                RedirectUri = _redirectUrl,
                Scope = _scope,
            };

            _oidc = new OidcClient(options);
        }

        /// <summary>
        /// Starts an interactive user login.
        /// </summary>
        /// <param name="initialClient">Optional initial client code.</param>
        /// <param name="initialAccount">Optional initial user account (email).</param>
        /// <param name="alwaysPrompt">Optional flag to always show login prompt.</param>
        /// <param name="openBrowser">Routine to open a browser when receiving the url. If null will attempt to open system browser (only for desktop).</param>
        /// <returns></returns>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task InteractiveLoginAsync(
            string initialClient = "", string initialAccount = "", bool alwaysPrompt = false,
            Action<string>? openBrowser = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(DesktopAuthHandler));

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

            var state = await _oidc.PrepareLoginAsync(extra);

            _pendingStates.AddOrUpdate(state.State, state, (key, exist) =>
            {
                // should never happen
                return state;
            });
            if (openBrowser != null)
            {
                openBrowser(state.StartUrl);
            }
            else
            {
                OpenDesktopBrowser(state.StartUrl);
            }
        }

        /// <summary>
        /// Opens a url in the system browser (desktop only).
        /// </summary>
        /// <param name="url">Url to open.</param>
        public static void OpenDesktopBrowser(string url)
        {
            if (string.IsNullOrEmpty(url)) return;

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
                return;
            }
            var authResp = new IdentityModel.Client.AuthorizeResponse(value);
            if (authResp.IsError)
            {
                RespondWithError(ctx, HttpStatusCode.BadRequest, authResp.Error, authResp.ErrorDescription);
                return;
            }
            else if (_pendingStates.TryRemove(authResp.State, out AuthorizeState? authState))
            {
                var result = await _oidc.ProcessResponseAsync(value, authState);
                if (result.IsError)
                {
                    RespondWithError(ctx, HttpStatusCode.BadRequest, result.Error, result.ErrorDescription);
                }
                else
                {
                    RespondWithSuccess(ctx, result);
                }
                return;
            }
            else if (AllowUnsolicited)
            {
                // essentially pretends the response is initiated from this handler
                //var oidc = _knownClients.GetOrAdd(oidcKey, _ =>
                //{
                //    var options = new OidcClientOptions
                //    {
                //        Authority = $"https://{server}/authen/identity/",
                //        ClientId = clientId,
                //        RedirectUri = _redirectUrl,
                //        Scope = authResp.Scope,
                //    };

                //    return new OidcClient(options);
                //});
                //authState = await oidc.PrepareLoginAsync();
                //authResp.State = authState.State;
                //authResp.SessionState = authState.
            }
            RespondWithError(ctx, HttpStatusCode.BadRequest, "bad_request", "This auth response cannot be verified.");
        }

        private void RespondWithSuccess(HttpListenerContext? ctx, LoginResult result)
        {
            if (ctx != null)
            {
                try
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                    ctx.Response.Headers["Content-Type"] = "text/html";
                    using (var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8))
                    {
                        var content = HtmlTemplate.Generate($"{HtmlTemplate.AppName} Sign-in Success", "You can close this window now.");
                        writer.Write(content);
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
                    ctx.Response.Headers["Content-Type"] = "text/html";
                    using (var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8))
                    {
                        var content = HtmlTemplate.Generate($"{HtmlTemplate.AppName} Sign-in Error", $"{errorCode} - {errorDescription}");
                        writer.Write(content);
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