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
        /// Name of the app to display.
        /// </summary>
        public string AppName { get; set; } = "Docufree";

        /// <summary>
        /// Default html content.
        /// </summary>
        public static string DefaultContent { get; } = Resources.HtmlTemplate;

        internal string Generate(string title, string body)
        {
            var template = Content ?? DefaultContent;
            return template
                .Replace("{{title}}", title)
                .Replace("{{body}}", body);
        }
    }
}
