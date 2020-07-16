namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;
	using System.Security.Claims;


	/// <summary>
	///		A context object containing information about the result of the user authenticating with the CAS server.
	/// </summary>
	public class CasResultContext : ResultContext<CasOptions>
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		/// <summary>
		///		The username of the CAS user.
		/// </summary>
		public string Username { get; }
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Default constructor.
		/// </summary>
		/// <param name="httpContext"></param>
		/// <param name="authenticationScheme"></param>
		/// <param name="casOptions"></param>
		/// <param name="claimsPrincipal"></param>
		/// <param name="authenticationProperties"></param>
		/// <param name="username"></param>
		public CasResultContext(HttpContext httpContext, AuthenticationScheme authenticationScheme, CasOptions casOptions, ClaimsPrincipal
			claimsPrincipal, AuthenticationProperties authenticationProperties, string username)
			: base(httpContext, authenticationScheme, casOptions)
		{
			Principal = claimsPrincipal;
			Properties = authenticationProperties;
			Username = username;
		}
		#endregion Methods
	}
}
