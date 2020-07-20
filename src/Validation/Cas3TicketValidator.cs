namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System;
	using System.Security.Claims;
	using System.Threading.Tasks;
	using System.Xml.Linq;

	public class Cas3TicketValidator : ICasTicketValidator
	{
		#region Constants/Enums
		private const string SERVICE_RESPONSE_XML_NAMESPACE = "http://www.yale.edu/tp/cas";
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		private ClaimsIdentity BuildIdentity(CasOptions casOptions, AuthenticationScheme authenticationScheme, string username, XContainer
			successNode, XNamespace @namespace)
		{
			// Use the specified claims issuer by default, otherwise use the authentication scheme name
			var claimsIssuer = casOptions.ClaimsIssuer ?? authenticationScheme.Name;

			var claimsIdentity = new ClaimsIdentity(claimsIssuer);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, username, ClaimValueTypes.String, claimsIssuer));

			// Process, if it exists, the "attributes" node of the response to add each attribute as a claim to the user's identity
			// NOTE: specifying attributes as part of a response from the /serviceValidate (CASv2) endpoint is not an official part of the
			//       specification. Due to the length of time it took to formalize CASv3, many CAS server implementations began providing the
			//       attributes via the CASv2 responses as it was simply ignored by clients that do not support it. This client is supporting it to
			//       be as feature-full as possible, but the CAS server itself must support attributes via CASv2 in order for this client to be able
			//       to consume them.
			var attributesParent = string.IsNullOrEmpty(casOptions.AttributesParentNodeName) ? "attributes" : casOptions.AttributesParentNodeName;
			var attributesNode = successNode.Element(@namespace + attributesParent);
			var nameIdentifierValue = username;

			if (attributesNode != null)
			{
				foreach (var element in attributesNode.Elements())
				{
					if (casOptions.NameIdentifierAttribute != null && element.Name.LocalName == casOptions.NameIdentifierAttribute)
					{
						nameIdentifierValue = element.Value;
					}

					claimsIdentity.AddClaim(new Claim(element.Name.LocalName, element.Value));
				}
			}

			claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameIdentifierValue, ClaimValueTypes.String, claimsIssuer));

			return claimsIdentity;
		}

		public async Task<AuthenticationTicket> ValidateTicketAsync(HttpContext httpContext, AuthenticationProperties authenticationProperties,
			AuthenticationScheme authenticationScheme, CasOptions casOptions, string ticket, string service)
		{
			var validationEndpoint = casOptions == null ?
				string.IsNullOrEmpty(casOptions.CasValidationUrl) ?
					$"{casOptions.CasServerUrlBase}/serviceValidate" :
					casOptions.CasValidationUrl :
				casOptions.CasValidationUrl;
			var validationUrl = $"{validationEndpoint}?service={service}&ticket={Uri.EscapeDataString(ticket)}";

			var validationResponse = await casOptions.Backchannel.GetAsync(validationUrl, httpContext.RequestAborted);
			validationResponse.EnsureSuccessStatusCode();

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

			var identity = BuildIdentity(casOptions, authenticationScheme, validatedUsername, successNode, serviceResponseNamespace);
			var ticketContext = new CasResultContext(httpContext, authenticationScheme, casOptions, new ClaimsPrincipal(identity),
				authenticationProperties, validatedUsername);

			await casOptions.Events.CreatingTicket(ticketContext);

			return new AuthenticationTicket(ticketContext.Principal, ticketContext.Properties, authenticationScheme.Name);
		}
		#endregion Methods
	}
}
