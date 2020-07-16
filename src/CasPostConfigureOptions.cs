namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.DataProtection;
	using Microsoft.Extensions.Options;


	public class CasPostConfigureOptions : IPostConfigureOptions<CasOptions>
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		private readonly IDataProtectionProvider _dataProtectionProvider;
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Default constructor.
		/// </summary>
		/// <param name="dataProtectionProvider">
		///		An instance of <see cref="IDataProtectionProvider"/> provided via dependency injection
		/// </param>
		public CasPostConfigureOptions(IDataProtectionProvider dataProtectionProvider)
		{
			// Store a local instance of the data protection provider
			_dataProtectionProvider = dataProtectionProvider;
		}

		public void PostConfigure(string name, CasOptions casOptions)
		{
			// Use the DI-provided data protection provider, if not specified in the CAS options object
			casOptions.DataProtectionProvider = casOptions.DataProtectionProvider ?? _dataProtectionProvider;

			if (casOptions.StateDataFormat == null)
			{
				var dataProtector = casOptions.DataProtectionProvider.CreateProtector(typeof(CasHandler).FullName, name, "v1");
				casOptions.StateDataFormat = new PropertiesDataFormat(dataProtector);
			}

			if (casOptions.Backchannel == null)
			{
				// Configure default backchannel options here
			}
		}
		#endregion Methods
	}
}
