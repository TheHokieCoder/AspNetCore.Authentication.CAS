namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using System;
	using System.Threading.Tasks;


	public class CasEvents : RemoteAuthenticationEvents
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		/// <summary>
		///		TODO: document this property
		/// </summary>
		public Func<CasResultContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public Func<RedirectContext<CasOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
		{
			context.Response.Redirect(context.RedirectUri);
			return Task.CompletedTask;
		};
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		TODO: document this method
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public virtual Task CreatingTicket(CasResultContext context) => OnCreatingTicket(context);

		/// <summary>
		///		TODO: document this method
		/// </summary>
		/// <param name="context"></param>
		/// <returns></returns>
		public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<CasOptions> context) => OnRedirectToAuthorizationEndpoint(context);
		#endregion Methods
	}
}
