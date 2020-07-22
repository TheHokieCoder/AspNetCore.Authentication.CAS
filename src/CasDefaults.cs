namespace AspNetCore.Authentication.CAS
{
	/// <summary>
	///		A collection of constants and default values used by the authentication middleware.
	/// </summary>
	public static class CasDefaults
	{
		/// <summary>
		///		A collection of constants and default values relating to the authentication scheme used by the authentication middleware.
		/// </summary>
		public static class AuthenticationScheme
		{
			/// <summary>
			///		The display name of the authentication scheme used by the authentication middleware.
			/// </summary>
			public const string DISPLAY_NAME = "CAS";

			/// <summary>
			///		The identifier of the authentication scheme used by the authentication middleware.
			/// </summary>
			public const string SCHEME = "CAS";
		}
	}
}
