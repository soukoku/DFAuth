using IdentityModel.OidcClient;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DF.Auth
{
    /// <summary>
    /// Used to periodically renew access token with a refresh token.
    /// </summary>
    public class AccessTokenRefresher
    {
        private OidcClient _client;
        CancellationTokenSource _stopToken = new CancellationTokenSource();
        private string? _refreshToken;

        /// <summary>
        /// Ctor.
        /// </summary>
        /// <param name="client">The client that was used to get the token.</param>
        internal AccessTokenRefresher(OidcClient client)
        {
            _client = client;
        }

        /// <summary>
        /// Starts the periodic renewal process as necessary.
        /// </summary>
        /// <param name="refreshToken">The refresh token value.</param>
        /// <param name="accessToken"></param>
        /// <param name="accessTokenExpiration"></param>
        /// <exception cref="ArgumentException"></exception>
        public void Start(string refreshToken, string accessToken, DateTimeOffset accessTokenExpiration)
        {
            _stopToken.Cancel();
            if (string.IsNullOrEmpty(refreshToken)) return;

            _stopToken = new CancellationTokenSource();
            _refreshToken = refreshToken;
            AccessToken = accessToken;
            AccessTokenExpiration = accessTokenExpiration;

            _ = RenewIfNecessary();
        }

        /// <summary>
        /// Stops the renewal process.
        /// </summary>
        public void Stop()
        {
            _stopToken?.Cancel();
        }

        /// <summary>
        /// The current access token.
        /// </summary>
        public string AccessToken { get; private set; } = "";

        /// <summary>
        /// The expiration time of the <see cref="AccessToken"/>.
        /// </summary>
        public DateTimeOffset AccessTokenExpiration { get; private set; }

        /// <summary>
        /// Event raised when the access token has been refreshed.
        /// </summary>
        public event EventHandler? RefreshSuccess;

        /// <summary>
        /// Event raised when the access token failed to refresh.
        /// Event args is the error message.
        /// </summary>
        public event EventHandler<string>? RefreshFail;

        private async Task RenewIfNecessary()
        {
            if (_stopToken.IsCancellationRequested) return;

            // attempt to renew every 30s when it's < 5 min before it expires
            var validFor = AccessTokenExpiration.Subtract(DateTimeOffset.Now);
            if (validFor.TotalMinutes > 5)
            {
                var sleepFor = validFor.Subtract(TimeSpan.FromMinutes(5));
                try
                {
                    await Task.Delay(sleepFor, _stopToken.Token);
                    _ = RenewIfNecessary();
                }
                catch (TaskCanceledException) { }
            }
            else
            {
                bool success = false;
                try
                {
                    var result = await _client.RefreshTokenAsync(_refreshToken);
                    if (result.IsError)
                    {
                        RefreshFail?.Invoke(this, $"{result.Error} - {result.ErrorDescription}");
                    }
                    else
                    {
                        success = true;
                        AccessToken = result.AccessToken;
                        AccessTokenExpiration = result.AccessTokenExpiration;
                        if (!string.IsNullOrEmpty(result.RefreshToken))
                        {
                            _refreshToken = result.RefreshToken;
                        }
                        RefreshSuccess?.Invoke(this, EventArgs.Empty);
                    }
                }
                catch (Exception ex)
                {
                    RefreshFail?.Invoke(this, ex.Message);
                }
                if (!success)
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30), _stopToken.Token);
                        _ = RenewIfNecessary();
                    }
                    catch (TaskCanceledException) { }
                }
            }
        }
    }
}
