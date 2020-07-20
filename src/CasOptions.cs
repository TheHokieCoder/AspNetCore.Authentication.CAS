namespace AspNetCore.Authentication.CAS
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Http;


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
		///		The caption text that can be displayed on a sign-in user interface.
		/// </summary>
		public string Caption { get; set; }

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
		///		TODO: document this property
		/// </summary>
		public bool EscapeServiceString { get; set; } = true;

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public new CasEvents Events
		{
			get => (CasEvents)base.Events;
			set => base.Events = value;
		}

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public bool Gateway { get; set; }

		/// <summary>
		///		The name of the CAS attribute to be used to populate the value for the NameIdenitifer claim for ASP.NET Core authentication.
		/// </summary>
		public string NameIdentifierAttribute { get; set; }

		/// <summary>
		///		Indicates whether or not clients should always be forced to authenticate (true) or if an existing, valid service ticket will suffice
		///		for authentication (false).
		/// </summary>
		/// <remarks>
		///		Setting this option to "true" effectively disables single sign-on (SSO) for the application as the client will always be required to
		///		present credentials.
		/// </remarks>
		public bool Renew { get; set; }

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public bool ServiceForceHttps { get; set; } = false;

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public string ServiceHost { get; set; }

		/// <summary>
		///		The namespace the service ticket validator should use when parsing responses from the validation endpoint.
		/// </summary>
		public string ServiceResponseNamespace { get; set; }

		/// <summary>
		///		TODO: document this property
		/// </summary>
		public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

		/// <summary>
		///		The implementation of <see cref="Validation.ICasTicketValidator"/> to be used to validate service tickets returned by the CAS server.
		/// </summary>
		public Validation.ICasTicketValidator TicketValidator { get; set; }
		#endregion Fields/Properties

		#region Methods
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
