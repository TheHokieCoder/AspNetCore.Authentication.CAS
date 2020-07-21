namespace AspNetCore.Authentication.CAS.Validation
{
	using Microsoft.AspNetCore.Authentication;
	using System.Security.Claims;
	using System.Xml.Linq;


	/// <summary>
	///		Utility functions that support the CAS ticket validators.
	/// </summary>
	internal static class CasTicketValidatorUtilities
	{
		#region Constants/Enums
		/// <summary>
		///		The default name of the node in an XML service response containing CAS attributes of the identity.
		/// </summary>
		private const string ATTRIBUTES_PARENT_NODE_NAME_DEFAULT = "attributes";
		#endregion Constants/Enums

		#region Fields/Properties
		#endregion Fields/Properties

		#region Methods
		/// <summary>
		///		Builds an instance of <see cref="ClaimsIdentity"/> containing the identity specified in the response from a CAS server validation
		///		endpoint.
		/// </summary>
		/// <param name="casOptions">
		///		The store of properties related to the CAS authentication middleware
		/// </param>
		/// <param name="authenticationScheme">
		///		Information about the authentication scheme being used
		/// </param>
		/// <param name="authenticatedUsername">
		///		The username that has been authenticated by the CAS server
		/// </param>
		/// <returns>
		///		A <see cref="ClaimsIdentity"/> instance populated with the identity and attributes of the authenticated user
		/// </returns>
		internal static ClaimsIdentity BuildClaimsIdentity(CasOptions casOptions, AuthenticationScheme authenticationScheme, string
			authenticatedUsername)
		{
			// Use the specified claims issuer by default, otherwise use the authentication scheme name
			var claimsIssuer = casOptions.ClaimsIssuer ?? authenticationScheme.Name;

			// Generate the new claims identity and populate it with a claim for the username
			var claimsIdentity = new ClaimsIdentity(claimsIssuer);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, authenticatedUsername, ClaimValueTypes.String, claimsIssuer));
			claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, authenticatedUsername, ClaimValueTypes.String, claimsIssuer));

			// Return the claims identity to the caller
			return claimsIdentity;
		}


		/// <summary>
		///		Builds an instance of <see cref="ClaimsIdentity"/> containing the identity specified in the response from a CAS server validation
		///		endpoint.
		/// </summary>
		/// <param name="casOptions">
		///		The store of properties related to the CAS authentication middleware
		/// </param>
		/// <param name="authenticationScheme">
		///		Information about the authentication scheme being used
		/// </param>
		/// <param name="authenticatedUsername">
		///		The username that has been authenticated by the CAS server
		/// </param>
		/// <param name="successNode">
		///		The XML node, from the service response, containing the details of the successful authentication
		/// </param>
		/// <param name="namespace">
		///		The namespace that is to be used when parsing the attributes from the service response
		/// </param>
		/// <returns>
		///		A <see cref="ClaimsIdentity"/> instance populated with the identity and attributes of the authenticated user
		/// </returns>
		internal static ClaimsIdentity BuildClaimsIdentity(CasOptions casOptions, AuthenticationScheme authenticationScheme, string
		authenticatedUsername, XContainer successNode, XNamespace @namespace)
		{
			// Use the specified claims issuer by default, otherwise use the authentication scheme name
			var claimsIssuer = casOptions.ClaimsIssuer ?? authenticationScheme.Name;

			// Generate the new claims identity and populate it with a claim for the username
			var claimsIdentity = new ClaimsIdentity(claimsIssuer);
			claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, authenticatedUsername, ClaimValueTypes.String, claimsIssuer));

			// Process, if it exists, the "attributes" node of the response to add each attribute as a claim to the user's identity
			var attributesParent = string.IsNullOrEmpty(casOptions.AttributesParentNodeName) ? ATTRIBUTES_PARENT_NODE_NAME_DEFAULT :
				casOptions.AttributesParentNodeName;
			var attributesNode = successNode.Element(@namespace + attributesParent);

			// Default to the authenticated username to account for the scenario where a specific value for the NameIdentifier claim is not specified
			// via a CAS attribute
			var nameIdentifierValue = authenticatedUsername;

			if (attributesNode != null)
			{
				// Process each attribute node
				foreach (var element in attributesNode.Elements())
				{
					if (casOptions.NameIdentifierAttribute != null && element.Name.LocalName == casOptions.NameIdentifierAttribute)
					{
						// Store the specified value for the NameIdentifier claim from the CAS attribute
						nameIdentifierValue = element.Value;
					}

					// Add the CAS attribute as a claim
					claimsIdentity.AddClaim(new Claim(element.Name.LocalName, element.Value));
				}
			}

			// Add the NameIdentifier claim
			claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameIdentifierValue, ClaimValueTypes.String, claimsIssuer));

			// Return the claims identity to the caller
			return claimsIdentity;
		}
		#endregion Methods
	}
}
