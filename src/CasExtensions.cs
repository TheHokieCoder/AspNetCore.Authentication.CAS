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
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Adds the CAS remote authentication scheme to the authentication middleware.
		/// </summary>
		///	<returns>
		///		The authentication builder that has the CAS remote authentication scheme configured for use
		/// </returns>
		/// <remarks>
		///		This overload of the extension method uses the default values provided in <see cref="CasDefaults.AuthenticationScheme"/> to specify
		///		the authentication scheme and display name, and provides an empty object for the configuration options.
		/// </remarks>
		public static AuthenticationBuilder AddCas(this AuthenticationBuilder builder) =>
			builder.AddCas(CasDefaults.AuthenticationScheme.SCHEME, CasDefaults.AuthenticationScheme.DISPLAY_NAME, _ => { });

		/// <summary>
		///		Adds the CAS remote authentication scheme to the authentication middleware.
		/// </summary>
		/// <param name="builder">
		///		The authentication builder
		/// </param>
		/// <param name="configureOptions">
		///		An action method that specifies CAS options
		/// </param>
		/// <returns>
		///		The authentication builder that has the CAS remote authentication scheme configured for use
		/// </returns>
		/// <remarks>
		///		This overload of the extension method uses the default values provided in <see cref="CasDefaults.AuthenticationScheme"/> to specify
		///		the authentication scheme and display name.
		/// </remarks>
		public static AuthenticationBuilder AddCas(this AuthenticationBuilder builder, Action<CasOptions> configureOptions) =>
			builder.AddCas(CasDefaults.AuthenticationScheme.SCHEME, CasDefaults.AuthenticationScheme.DISPLAY_NAME, configureOptions);

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
		public static AuthenticationBuilder AddCas(this AuthenticationBuilder builder, string authenticationScheme, string displayName,
			Action<CasOptions> configureOptions)
		{
			builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CasOptions>, CasPostConfigureOptions>());

			// Add IHttpClientFactory to the services collection so that an HTTP client can be injected into the CAS client for back-channel calls
			// to the CAS server.
			builder.Services.AddHttpClient();

			return builder.AddRemoteScheme<CasOptions, CasRemoteAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
		}
		#endregion Methods
	}
}
