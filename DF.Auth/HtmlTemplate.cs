using System.IO;
using System.Reflection;

namespace DF.Auth
{
    /// <summary>
    /// Template for displaying response handling result.
    /// </summary>
    public class HtmlTemplate
    {
        /// <summary>
        /// The custom html content to use as template.
        /// Should have {{title}} and {{body}} placeholders.
        /// </summary>
        public string? Content { get; set; }

        /// <summary>
        /// Default html content.
        /// </summary>
        public string DefaultContent { get; } = GetResourceString("page.html");

        private static string GetResourceString(string resourceName)
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"DF.Auth.{resourceName}"))
            {
                if (stream == null) return "";
                else
                {
                    using (var reader = new StreamReader(stream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }

        internal string Generate(string title, string body)
        {
            var template = Content ?? DefaultContent;
            return template
                .Replace("{{title}}", title)
                .Replace("{{body}}", body);
        }
    }
}
