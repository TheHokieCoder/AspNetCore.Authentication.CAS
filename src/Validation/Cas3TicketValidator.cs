namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System;
	using System.Security.Claims;
	using System.Threading.Tasks;
	using System.Xml.Linq;


	/// <summary>
	///		A CAS ticket validator that implements version 3.0 of the CAS specification.
	/// </summary>
	public class Cas3TicketValidator : ICasTicketValidator
	{
		#region Constants/Enums
		/// <summary>
		///		The XML namespace that the service response is expected to conform to.
		/// </summary>
		private const string SERVICE_RESPONSE_XML_NAMESPACE = "http://www.yale.edu/tp/cas";

		/// <summary>
		///		The path at which the validation endpoint is expected to exist, per CAS specification.
		/// </summary>
		private const string VALIDATION_ENDPOINT_PATH = "/p3/serviceValidate";
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

			// Read the response body and parse the XML for the username
			var responseBody = await validationResponse.Content.ReadAsStringAsync();
			var responseDocument = XDocument.Parse(responseBody);
			XNamespace serviceResponseNamespace = string.IsNullOrEmpty(casOptions.ServiceResponseNamespace) ? SERVICE_RESPONSE_XML_NAMESPACE :
				casOptions.ServiceResponseNamespace;
			var serviceResponse = responseDocument.Element(serviceResponseNamespace + "serviceResponse");
			var successNode = serviceResponse?.Element(serviceResponseNamespace + "authenticationSuccess");
			var userNode = successNode?.Element(serviceResponseNamespace + "user");
			var validatedUsername = userNode?.Value;

			if (string.IsNullOrEmpty(validatedUsername))
			{
				// The response from the validation endpoint did not contain a confirmed username, so it must be assumed that the ticket is invalid
				return null;
			}

			// Build a claims identity for .NET Core using the username and claims provided by the CAS server validation endpoint
			var identity = CasTicketValidatorUtilities.BuildClaimsIdentity(casOptions, authenticationScheme, validatedUsername, successNode,
				serviceResponseNamespace);

			// Build a context object containing information about the validated user and then raise an event indicating that a validated service
			// ticket has been created
			var ticketContext = new CasResultContext(httpContext, authenticationScheme, casOptions, new ClaimsPrincipal(identity),
				authenticationProperties, validatedUsername);
			await casOptions.Events.CreatingTicket(ticketContext);

			// Return a newly-created authentication ticket to the authentication middleware
			return new AuthenticationTicket(ticketContext.Principal, ticketContext.Properties, authenticationScheme.Name);
		}
		#endregion Methods
	}
}
