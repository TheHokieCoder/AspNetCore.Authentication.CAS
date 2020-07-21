namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System.Threading.Tasks;


	/// <summary>
	///		The interface a CAS ticket validator must implement to be utilized by the CAS authentication handler.
	/// </summary>
	public interface ICasTicketValidator
	{
		/// <summary>
		///		Validates the specified service ticket against the CAS server's validation endpoint. If validation succeeds, an authentication ticket
		///		is created for .NET Core authentication and returned. If validation fails, a null value is returned.
		/// </summary>
		/// <param name="httpContext">
		///		The context of the HTTP request in which authentication is occuring
		/// </param>
		/// <param name="authenticationProperties">
		///		The store of properties related to authentication session
		/// </param>
		/// <param name="authenticationScheme">
		///		Information about the authentication scheme being used
		/// </param>
		/// <param name="casOptions">
		///		The store of properties related to the CAS authentication middleware
		/// </param>
		/// <param name="ticket">
		///		The identifier of the service ticket created as a result of successful authentication against the CAS server
		/// </param>
		/// <param name="service">
		///		The URL of the service (web application) for which the authentication and validation are occuring
		/// </param>
		/// <returns>
		///		An instance of <see cref="AuthenticationTicket"/> containing information about the authenticated identity
		/// </returns>
		Task<AuthenticationTicket> ValidateTicketAsync(HttpContext httpContext, AuthenticationProperties authenticationProperties,
			AuthenticationScheme authenticationScheme, CasOptions casOptions, string ticket, string service);
	}
}
