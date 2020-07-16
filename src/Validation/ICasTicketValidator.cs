namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System.Threading.Tasks;


	public interface ICasTicketValidator
	{
		Task<AuthenticationTicket> ValidateTicketAsync(HttpContext httpContext, AuthenticationProperties authenticationProperties,
			AuthenticationScheme authenticationScheme, CasOptions casOptions, string ticket, string service);
	}
}
