namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Options;
	using System;
	using System.Text.Encodings.Web;
	using System.Threading.Tasks;


	/// <summary>
	///		A remote authentication handler that supports the CAS protocol.
	/// </summary>
	internal class CasRemoteAuthenticationHandler : RemoteAuthenticationHandler<CasOptions>
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		/// <summary>
		///		A collection of remote authentication (CAS) events that allow the application to have control at certain points during the remote
		///		authentication process.
		/// </summary>
		protected new CasEvents Events
		{
			get => (CasEvents)base.Events;
			set => base.Events = value;
		}
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Builds a URL for the CAS server to redirect the user to once the authentication process is complete.
		/// </summary>
		/// <param name="state">
		///		The serialized (and potentially encrypted) authentication state data that represents the current, authenticated session.
		/// </param>
		/// <returns>
		///		A URL the CAS server should redirect the user to once the authentication process is complete
		/// </returns>
		private string BuildReturnToURL(string state)
		{
			var host = Request.Host;
			var scheme = Options.ServiceForceHttps ? "https" : Request.Scheme;

			if (!string.IsNullOrWhiteSpace(Options.ServiceHost))
			{
				// Build a host (and potentially port) string from the configured option, after replacing any trailing slashes
				host = new HostString(Options.ServiceHost.Replace("/", ""));
			}

			// Build the full URL for the CAS server to redirect to after authentication
			var returnToURL = $"{scheme}://{host}{Request.PathBase}{Options.CallbackPath}?state={Uri.EscapeDataString(state)}";

			return Uri.EscapeDataString(returnToURL);
		}

		/// <summary>
		///		Default constructor.
		/// </summary>
		/// <remarks>
		///		See https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1 for more details (which
		///		are currently not documented).
		/// </remarks>
		public CasRemoteAuthenticationHandler(IOptionsMonitor<CasOptions> casOptions, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(casOptions, logger, encoder, clock) { }

		/// <summary>
		///		Creates a new instance of the <see cref="CasEvents"/> class.
		/// </summary>
		/// <returns>
		///		An awaitable task containing the object that is the new instance of <see cref="CasEvents"/>
		/// </returns>
		protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new CasEvents());

		/// <summary>
		///		Method that handles authentication challenges by redirecting the request to the CAS login endpoint.
		/// </summary>
		/// <param name="properties">
		///		The dictionary containing details about the authentication session
		/// </param>
		/// <returns>
		///		An awaitable task
		/// </returns>
		protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
		{
			if (string.IsNullOrEmpty(properties.RedirectUri))
			{
				properties.RedirectUri = CurrentUri;
			}

			// Generate a correlation ID to help protect against CSRF attacks
			GenerateCorrelationId(properties);

			var returnToURL = BuildReturnToURL(Options.StateDataFormat.Protect(properties));

			var authorizationEndpoint = $"{Options.CasServerUrlBase}/login?service={returnToURL}";

			if (Options.Renew)
			{
				// Add the renew query string parameter to the return URL
				authorizationEndpoint += "&renew=true";
			}

			if (Options.Gateway)
			{
				// Add the gateway query string parameter to the return URL
				authorizationEndpoint += "&gateway=true";
			}

			// Create a context object that describes the redirection of the authentication challenge request to the CAS server
			var redirectContext = new RedirectContext<CasOptions>(Context, Scheme, Options, properties, authorizationEndpoint);

			// Raise the redirection event
			await Options.Events.RedirectToAuthorizationEndpoint(redirectContext);
		}

		/// <summary>
		///		Handles requests from the remote authentication (CAS) server.
		/// </summary>
		/// <returns>
		///		An awaitable task containing the result of verifying the request
		/// </returns>
		protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
		{
			var query = Request.Query;
			var state = query["state"];

			// Decrypt the authentication session state data
			AuthenticationProperties properties = Options.StateDataFormat.Unprotect(state);
			if (properties == null)
			{
				// The request either did not contain the state data, or it was in an invalid format
				return HandleRequestResult.Fail("The state data is missing from the request, or it is invalid.");
			}

			// Ensure that a correlation ID has been provided and that it is valid, pursuant to section 10.12 of the OAuth 2.0 Authorization Framework
			// https://tools.ietf.org/html/rfc6749#section-10.12
			if (!ValidateCorrelationId(properties))
			{
				return HandleRequestResult.Fail("Correlation of the user and request failed.");
			}

			var serviceTicket = query["ticket"];
			if (string.IsNullOrEmpty(serviceTicket))
			{
				return HandleRequestResult.Fail("The service ticket identifier is missing from the request.");
			}

			// Validate the service ticket presented in the authentication result request
			var authenticationTicket = await Options.TicketValidator.ValidateTicketAsync(Context, properties, Scheme, Options, serviceTicket,
				BuildReturnToURL(state));
			if (authenticationTicket == null)
			{
				// The ticket validator was unable to validate the ticket and obtain information about the authenticated user
				return HandleRequestResult.Fail("Failed to validate the service ticket with the CAS server.");
			}

			// All checks have passed, so the user may now be considered authenticated with the application
			return HandleRequestResult.Success(authenticationTicket);
		}
		#endregion Methods
	}
}
