namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;


	/// <summary>
	///		An implementation of <see cref="RemoteAuthenticationOptions"/> specifically for remote authentication with a CAS server.
	/// </summary>
	public class CasOptions : RemoteAuthenticationOptions
	{
		#region Constants/Enums
		#endregion Constants/Enums

		#region Fields/Properties
		/// <summary>
		///		The name of the XML document node that contains the CAS user attributes.
		/// </summary>
		/// <remarks>
		///		Defaults to "attributes" for the CAS standard XML node name of "cas:attributes".
		/// </remarks>
		public string AttributesParentNodeName { get; set; } = "attributes";

		/// <summary>
		///		The base URL of the CAS server.
		/// </summary>
		public string CasServerUrlBase { get; set; }

		/// <summary>
		///		The URL at which the service ticket validation endpoint exists.
		/// </summary>
		/// <remarks>
		///		This property is useful in scenarios where the service ticket validation occurs on a server separate from authentication.
		/// </remarks>
		public string CasValidationUrl { get; set; }

		/// <summary>
		///		An object that provides access to events that occur during the CAS authentication process.
		/// </summary>
		/// <remarks>
		///		By default, this property will reference the base <see cref="RemoteAuthenticationEvents"/> property, but it can be overridden by an
		///		instance of <see cref="CasEvents"/>.
		/// </remarks>
		public new CasEvents Events
		{
			get => (CasEvents)base.Events;
			set => base.Events = value;
		}

		/// <summary>
		///		Indicates whether or not the client should indicate to the CAS server that it should use gateway mode, which means that authentication
		///		is not critical to access the resource.
		/// </summary>
		/// <remarks>
		///		See https://apereo.github.io/cas/6.2.x/protocol/CAS-Protocol-Specification.html#211-parameters for more information about the
		///		"gateway" parameter.
		/// </remarks>
		public bool Gateway { get; set; }

		/// <summary>
		///		The name of the CAS attribute to be used to populate the value for the NameIdenitifer claim for ASP.NET Core authentication.
		/// </summary>
		public string NameIdentifierAttribute { get; set; }

		/// <summary>
		///		Indicates whether or not clients should always be forced to present credientials (true) or if an existing, valid service ticket will
		///		suffice for authentication (false).
		/// </summary>
		/// <remarks>
		///		Setting this option to "true" effectively disables single sign-on (SSO) for the application as the client will always be required to
		///		present credentials. See https://apereo.github.io/cas/6.2.x/protocol/CAS-Protocol-Specification.html#211-parameters for more
		///		information about the "renew" parameter.
		/// </remarks>
		public bool Renew { get; set; }

		/// <summary>
		///		Force the CAS client to always present the service (client application) URL using the HTTPS scheme. 
		/// </summary>
		/// <remarks>
		///		This property is useful in scenarios where CAS servers are configured to refuse insecure (HTTP) connections to services.
		/// </remarks>
		public bool ServiceForceHttps { get; set; } = false;

		/// <summary>
		///		The host name to be presented to the CAS server via the "service" parameter.
		/// </summary>
		public string ServiceHost { get; set; }

		/// <summary>
		///		The namespace the service ticket validator should use when parsing responses from the validation endpoint.
		/// </summary>
		public string ServiceResponseNamespace { get; set; }

		/// <summary>
		///		The format with which details about the authentication session should be stored.
		/// </summary>
		public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

		/// <summary>
		///		The implementation of <see cref="Validation.ICasTicketValidator"/> to be used to validate service tickets returned by the CAS server.
		/// </summary>
		public Validation.ICasTicketValidator TicketValidator { get; set; }
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Default constructor.
		/// </summary>
		public CasOptions()
		{
			// Configure default CAS options
			CallbackPath = new PathString("/signin-cas");
			Events = new CasEvents();
			TicketValidator = new Validation.Cas3TicketValidator();
		}
		#endregion Methods
	}
}
