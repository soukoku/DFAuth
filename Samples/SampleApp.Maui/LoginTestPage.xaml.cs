using DF.Auth;
using Microsoft.Extensions.Configuration;

namespace SampleApp.Maui;

public partial class LoginTestPage : ContentPage
{
    private IConfiguration _config;
    private DesktopAuthHandler _handler;
    AccessTokenRefresher _refresher;

    public LoginTestPage()
    {
        InitializeComponent();
        _config = new ConfigurationBuilder()
            .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
            .AddJsonFile("appsettings.json", true)
            .AddUserSecrets<App>(true)
            .Build();
        boxServer.Text = _config["server"];
        boxClient.Text = _config["clientId"];
        boxPort.Text = _config["redirectPort"];
        boxPath.Text = _config["redirectPath"];
    }

    private void btnTest_Click(object sender, EventArgs e)
    {
        try
        {
            _handler?.Dispose();
            _refresher?.Stop();

            _handler = new DF.Auth.DesktopAuthHandler(boxServer.Text,
                boxClient.Text,
                _config["clientSecret"],
                handlerPath: boxPath.Text,
                localPort: int.Parse(boxPort.Text));
            _handler.HtmlTemplate.AppName = "Login Tester (Maui)";
            _handler.LoginCompleted += (s, result) =>
            {
                Dispatcher.Dispatch(() =>
                {
                    if (result.IsError)
                    {
                        boxResult.Text += $"Error: {result.Error} - {result.ErrorDescription}\n";
                    }
                    else
                    {
                        boxResult.Text += $"Success!\n";
                        boxResult.Text += $"Access token: {result.AccessToken}\n";
                        boxResult.Text += $"Expires at: {result.AccessTokenExpiration}\n";
                        boxResult.Text += $"Refresh token: {result.RefreshToken}\n";
                        boxResult.Text += $"ID token: {result.IdentityToken}\n";
                        boxResult.Text += "Claims:\n";
                        foreach (var claim in result.User.Claims)
                        {
                            boxResult.Text += $"\t{claim.Type}: {claim.Value}\n";
                        }
                        boxResult.Text += Environment.NewLine;
                        _refresher?.Start(result.RefreshToken, result.AccessToken, result.AccessTokenExpiration);
                    }
                });
            };
            _refresher = _handler.GetTokenRefresher();
            _refresher.RefreshFail += (s, err) =>
            {
                boxResult.Text += $"Failed to refresh token: {err}\n";
            };
            _refresher.RefreshSuccess += (s, e) =>
            {
                var refresh = s as AccessTokenRefresher;
                if (refresh != null)
                {
                    boxResult.Text += $"Token renewal success!\n";
                    boxResult.Text += $"Access token: {refresh.AccessToken}\n";
                    boxResult.Text += $"Expires at: {refresh.AccessTokenExpiration}\n";
                }
            };

            _ = _handler.InteractiveLoginAsync(
                initialClient: boxSite.Text,
                initialAccount: boxUser.Text,
                alwaysPrompt: ckPrompt.IsChecked);
        }
        catch (Exception ex)
        {
            boxResult.Text += $"Catch {ex}\n";
        }
    }
}