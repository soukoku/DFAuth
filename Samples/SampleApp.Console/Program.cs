using DF.Auth;
using Microsoft.Extensions.Configuration;


internal class Program
{
    private static async Task Main(string[] args)
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
            .AddJsonFile("appsettings.json", true)
            .AddUserSecrets<Program>(true)
            .Build();

        var auth = new DesktopAuthHandler(
            config["server"], config["clientId"], config["clientSecret"],
            handlerPath: config["redirectPath"],
            localPort: int.Parse(config["redirectPort"]));

        auth.HtmlTemplate.AppName = "DF Login Tester (Console)";
        auth.LoginCompleted += (s, result) =>
        {
            if (result.IsError)
            {
                Console.WriteLine($"Error: {result.Error} - {result.ErrorDescription}");
            }
            else
            {
                Console.WriteLine($"Success!");
                Console.WriteLine($"Access token: {result.AccessToken}");
                Console.WriteLine($"Expires at: {result.AccessTokenExpiration}");
                Console.WriteLine($"Refresh token: {result.RefreshToken}");
                Console.WriteLine($"ID token: {result.IdentityToken}");
                Console.WriteLine("Claims:");
                foreach (var claim in result.User.Claims)
                {
                    Console.WriteLine($"\t{claim.Type}: {claim.Value}");
                }
                Console.WriteLine();
                Console.WriteLine("Press Enter to exit...");
            }
        };


        if (IsYes(AskAnswer("Test login? (Y/n)")))
        {
            var prompt = IsYes(AskAnswer("Always prompt credentials? (Y/n)"));
            await auth.InteractiveLoginAsync(alwaysPrompt: prompt);
            Console.ReadLine();
        }
    }

    private static bool IsYes(string? answer)
    {
        return string.IsNullOrEmpty(answer) || string.Equals("Y", answer, StringComparison.OrdinalIgnoreCase);
    }

    static string? AskAnswer(string prompt)
    {
        Console.WriteLine(prompt);
        return Console.ReadLine();
    }
}