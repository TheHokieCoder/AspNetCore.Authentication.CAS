namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System;
	using System.Security.Claims;
	using System.Threading.Tasks;


	public class Cas1TicketValidator : ICasTicketValidator 
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		public async Task<AuthenticationTicket> ValidateTicketAsync(HttpContext httpContext, AuthenticationProperties authenticationProperties,
			AuthenticationScheme authenticationScheme, CasOptions casOptions, string ticket, string service)
		{
			var validationEndpoint = casOptions == null ?
				string.IsNullOrEmpty(casOptions.CasValidationUrl) ?
					$"{casOptions.CasServerUrlBase}/validate" :
					casOptions.CasValidationUrl :
				casOptions.CasValidationUrl;
			var validationUrl = $"{validationEndpoint}?service={service}&ticket={Uri.EscapeDataString(ticket)}";

			var validationResponse = await casOptions.Backchannel.GetAsync(validationUrl, httpContext.RequestAborted);
			validationResponse.EnsureSuccessStatusCode();

			var responseBody = await validationResponse.Content.ReadAsStringAsync();

			string validatedUsername = null;
			var responseParts = responseBody.Split('\n');
			if (responseParts.Length >= 2 && responseParts[0] == "yes")
			{
				validatedUsername = responseParts[1];
			}

			if (string.IsNullOrEmpty(validatedUsername))
			{
				return null;
			}

			var issuer = casOptions.ClaimsIssuer ?? authenticationScheme.Name;

			var claims = new[]
			{
				new Claim(ClaimTypes.NameIdentifier, validatedUsername, ClaimValueTypes.String, issuer),
				new Claim(ClaimTypes.Name, validatedUsername, ClaimValueTypes.String, issuer)
			};

			var identity = new ClaimsIdentity(claims, authenticationScheme.Name);
			var resultContext = new CasResultContext(httpContext, authenticationScheme, casOptions, new ClaimsPrincipal(identity),
				authenticationProperties, validatedUsername);

			await casOptions.Events.CreatingTicket(resultContext);

			return new AuthenticationTicket(resultContext.Principal, resultContext.Properties, authenticationScheme.Name);
		}
		#endregion Methods
	}
}
