namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.Extensions.DependencyInjection.Extensions;
	using Microsoft.Extensions.Options;
	using System;


	/// <summary>
	///		Extension methods that allow for adding the CAS authentication middleware to the request pipeline.
	/// </summary>
	public static class CasExtensions
	{
		#region Constants/Enums
		private const string AUTHENTICATION_SCHEME_DEFAULT = "CAS";

		private const string DISPLAY_NAME_DEFAULT = "CAS";
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		public static AuthenticationBuilder AddCas(this AuthenticationBuilder builder, Action<CasOptions> configureOptions)
		{
			return builder.AddCas(AUTHENTICATION_SCHEME_DEFAULT, DISPLAY_NAME_DEFAULT, configureOptions);
		}

		/// <summary>
		///		Adds the CAS remote authentication scheme to the authentication middleware.
		/// </summary>
		/// <param name="builder">
		///		The authentication builder
		/// </param>
		/// <param name="authenticationScheme">
		///		The name of the authentication scheme to use
		/// </param>
		/// <param name="displayName">
		///		The display name of the authentication scheme to use
		/// </param>
		/// <param name="configureOptions">
		///		An action method that specifies CAS options
		/// </param>
		/// <returns>
		///		The authentication builder that has the CAS remote authentication scheme configured for use
		/// </returns>
		public static AuthenticationBuilder AddCas(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<CasOptions> configureOptions)
		{
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CasOptions>, CasPostConfigureOptions>());

			return builder.AddRemoteScheme<CasOptions, CasRemoteAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
		}
		#endregion Methods
	}
}
