namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.DataProtection;
	using Microsoft.Extensions.Options;
	using System.Net.Http;


	/// <summary>
	///		Further configures the CAS options instance once it has been configured by the ASP.NET Core framework.
	/// </summary>
	public class CasPostConfigureOptions : IPostConfigureOptions<CasOptions>
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		/// <summary>
		///		A local instance of <see cref="IDataProtectionProvider"/> that allows for protecting state data related to an authenticated session.
		/// </summary>
		private readonly IDataProtectionProvider _dataProtectionProvider;

		/// <summary>
		///		A local instance of <see cref="IHttpClientFactory"/> that provides instances of <see cref="HttpClient"/> for back-channel'
		///		communication with the CAS server.
		/// </summary>
		private readonly IHttpClientFactory _httpClientFactory;
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Default constructor.
		/// </summary>
		/// <param name="dataProtectionProvider">
		///		An instance of <see cref="IDataProtectionProvider"/> provided from the services collection via dependency injection
		/// </param>
		/// <param name="httpClientFactory">
		///		An instance of <see cref="IHttpClientFactory"/> provided from the services collection via dependency injection
		/// </param>
		public CasPostConfigureOptions(IDataProtectionProvider dataProtectionProvider, IHttpClientFactory httpClientFactory)
		{
			// Store a local instance of the data protection provider
			_dataProtectionProvider = dataProtectionProvider;
			// Store a local instance of the HTTP client factory
			_httpClientFactory = httpClientFactory;
		}

		/// <summary>
		///		Method that is invoked in order to further configure the specified options instance.
		/// </summary>
		/// <param name="name">
		///		The name of the instance being configured.
		/// </param>
		/// <param name="casOptions">
		///		The options instance being configured.
		/// </param>
		public void PostConfigure(string name, CasOptions casOptions)
		{
			// Use the DI-provided data protection provider, if not specified in the CAS options object
			casOptions.DataProtectionProvider = casOptions.DataProtectionProvider ?? _dataProtectionProvider;

			if (casOptions.StateDataFormat == null)
			{
				// No explicit data format has been specified in the options instance, so create a default one
				var dataProtector = casOptions.DataProtectionProvider.CreateProtector(typeof(CasRemoteAuthenticationHandler).FullName, name, "v1");
				casOptions.StateDataFormat = new PropertiesDataFormat(dataProtector);
			}

			if (casOptions.Backchannel == null)
			{
				// No back-channel HTTP client has been specified in the options instance, so create and configure a default one
				casOptions.Backchannel = _httpClientFactory.CreateClient();
				casOptions.Backchannel.Timeout = casOptions.BackchannelTimeout;
				casOptions.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10MiB
				casOptions.Backchannel.DefaultRequestHeaders.Accept.ParseAdd("*/*");
				casOptions.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core CAS Handler");
				casOptions.Backchannel.DefaultRequestHeaders.ExpectContinue = false;
			}
		}
		#endregion Methods
	}
}
