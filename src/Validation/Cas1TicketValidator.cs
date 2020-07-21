namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System;
	using System.Security.Claims;
	using System.Threading.Tasks;


	/// <summary>
	///		A CAS ticket validator that implements version 1.0 of the CAS specification.
	/// </summary>
	public class Cas1TicketValidator : ICasTicketValidator 
	{
		#region Constants/Enums
		/// <summary>
		///		The path at which the validation endpoint is expected to exist, per CAS specification.
		/// </summary>
		private const string VALIDATION_ENDPOINT_PATH = "/service";
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		public async Task<AuthenticationTicket> ValidateTicketAsync(HttpContext httpContext, AuthenticationProperties authenticationProperties,
			AuthenticationScheme authenticationScheme, CasOptions casOptions, string ticket, string service)
		{

			string validationEndpoint;
			if (casOptions != null && !string.IsNullOrEmpty(casOptions.CasValidationUrl))
			{
				// Use the URL provided in the specified CasOptions instance
				validationEndpoint = casOptions.CasValidationUrl;
			}
			else
			{
				// Build the URL from the CAS server's base URL and the endpoint path as defined by the CAS specification
				validationEndpoint = $"{casOptions.CasServerUrlBase}{VALIDATION_ENDPOINT_PATH}";
			}
			// Build the full URL for the CAS server validation endpoint, along with query string parameters
			var validationUrl = $"{validationEndpoint}?service={service}&ticket={Uri.EscapeDataString(ticket)}";

			// Call the validation endpoint and await its response
			var validationResponse = await casOptions.Backchannel.GetAsync(validationUrl, httpContext.RequestAborted);

			// Throw an exception if the response from the validation endpoint does not indicate success
			validationResponse.EnsureSuccessStatusCode();

			// Read the response body and parse it for the username
			var responseBody = await validationResponse.Content.ReadAsStringAsync();
			string validatedUsername = null;
			var responseParts = responseBody.Split('\n');
			if (responseParts.Length >= 2 && string.Compare(responseParts[0], "yes", true) == 0)
			{
				validatedUsername = responseParts[1];
			}

			if (string.IsNullOrEmpty(validatedUsername))
			{
				// No username was present in the response, so the response is invalid and therefore no identity can be assumed
				return null;
			}

			// Build a claims identity for .NET Core using the username and claims provided by the CAS server validation endpoint
			var claimsIdentity = CasTicketValidatorUtilities.BuildClaimsIdentity(casOptions, authenticationScheme, validatedUsername);

			// Build a context object containing information about the validated user and then raise an event indicating that a validated service
			// ticket has been created
			var resultContext = new CasResultContext(httpContext, authenticationScheme, casOptions, new ClaimsPrincipal(claimsIdentity),
				authenticationProperties, validatedUsername);
			await casOptions.Events.CreatingTicket(resultContext);

			// Return a newly-created authentication ticket to the authentication middleware
			return new AuthenticationTicket(resultContext.Principal, resultContext.Properties, authenticationScheme.Name);
		}
		#endregion Methods
	}
}
