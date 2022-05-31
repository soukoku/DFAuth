using DF.Auth;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SampleApp.Wpf
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private IConfiguration _config;
        private DesktopAuthHandler? _handler;
        AccessTokenRefresher? _refresher;

        public MainWindow()
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

        private void btnTest_Click(object sender, RoutedEventArgs e)
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
                _handler.HtmlTemplate.AppName = "Login Tester (Wpf)";
                _handler.LoginCompleted += (s, result) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        if (result.IsError)
                        {
                            boxResult.AppendText($"Error: {result.Error} - {result.ErrorDescription}\n");
                        }
                        else
                        {
                            boxResult.AppendText($"Success!\n");
                            boxResult.AppendText($"Access token: {result.AccessToken}\n");
                            boxResult.AppendText($"Expires at: {result.AccessTokenExpiration}\n");
                            boxResult.AppendText($"Refresh token: {result.RefreshToken}\n");
                            boxResult.AppendText($"ID token: {result.IdentityToken}\n");
                            boxResult.AppendText("Claims:\n");
                            foreach (var claim in result.User.Claims)
                            {
                                boxResult.AppendText($"\t{claim.Type}: {claim.Value}\n");
                            }
                            boxResult.AppendText(Environment.NewLine);
                            _refresher?.Start(result.RefreshToken, result.AccessToken, result.AccessTokenExpiration);
                        }
                    });
                };
                _refresher = _handler.GetTokenRefresher();
                _refresher.RefreshFail += (s, err) =>
                {
                    boxResult.AppendText($"Failed to refresh token: {err}\n");
                };
                _refresher.RefreshSuccess += (s, e) =>
                {
                    var refresh = s as AccessTokenRefresher;
                    if (refresh != null)
                    {
                        boxResult.AppendText($"Token renewal success!\n");
                        boxResult.AppendText($"Access token: {refresh.AccessToken}\n");
                        boxResult.AppendText($"Expires at: {refresh.AccessTokenExpiration}\n");
                    }
                };

                _ = _handler.InteractiveLoginAsync(
                    initialClient: boxSite.Text,
                    initialAccount: boxUser.Text,
                    alwaysPrompt: ckPrompt.IsChecked.GetValueOrDefault());
            }
            catch (Exception ex)
            {
                boxResult.AppendText($"Catch {ex}\n");
            }
        }
    }
}
