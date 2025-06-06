// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    /// <summary>
    /// This resource provides the Identity Provider resource in Oracle Cloud Infrastructure Identity service.
    /// 
    /// **Deprecated.** For more information, see [Deprecated IAM Service APIs](https://docs.cloud.oracle.com/iaas/Content/Identity/Reference/deprecatediamapis.htm).
    /// 
    /// Creates a new identity provider in your tenancy. For more information, see
    /// [Identity Providers and Federation](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/federation.htm).
    /// 
    /// You must specify your tenancy's OCID as the compartment ID in the request object.
    /// Remember that the tenancy is simply the root compartment. For information about
    /// OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    /// 
    /// You must also specify a *name* for the `IdentityProvider`, which must be unique
    /// across all `IdentityProvider` objects in your tenancy and cannot be changed.
    /// 
    /// You must also specify a *description* for the `IdentityProvider` (although
    /// it can be an empty string). It does not have to be unique, and you can change
    /// it anytime with
    /// [UpdateIdentityProvider](https://docs.cloud.oracle.com/iaas/api/#/en/identity/20160918/IdentityProvider/UpdateIdentityProvider).
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testIdentityProvider = new Oci.Identity.IdentityProvider("test_identity_provider", new()
    ///     {
    ///         CompartmentId = tenancyOcid,
    ///         Description = identityProviderDescription,
    ///         Metadata = identityProviderMetadata,
    ///         MetadataUrl = identityProviderMetadataUrl,
    ///         Name = identityProviderName,
    ///         ProductType = identityProviderProductType,
    ///         Protocol = identityProviderProtocol,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformAttributes = identityProviderFreeformAttributes,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// IdentityProviders can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Identity/identityProvider:IdentityProvider test_identity_provider "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Identity/identityProvider:IdentityProvider")]
    public partial class IdentityProvider : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of your tenancy.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Extra name value pairs associated with this identity provider. Example: `{"clientId": "app_sf3kdjf3"}`
        /// </summary>
        [Output("freeformAttributes")]
        public Output<ImmutableDictionary<string, string>> FreeformAttributes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Output("inactiveState")]
        public Output<string> InactiveState { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The XML that contains the information required for federating.
        /// </summary>
        [Output("metadata")]
        public Output<string> Metadata { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The URL for retrieving the identity provider's metadata, which contains information required for federating.
        /// </summary>
        [Output("metadataUrl")]
        public Output<string> MetadataUrl { get; private set; } = null!;

        /// <summary>
        /// The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).  Example: `IDCS`
        /// </summary>
        [Output("productType")]
        public Output<string> ProductType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The protocol used for federation.  Example: `SAML2` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("protocol")]
        public Output<string> Protocol { get; private set; } = null!;

        /// <summary>
        /// The URL to redirect federated users to for authentication with the identity provider.
        /// </summary>
        [Output("redirectUrl")]
        public Output<string> RedirectUrl { get; private set; } = null!;

        /// <summary>
        /// The identity provider's signing certificate used by the IAM Service to validate the SAML2 token.
        /// </summary>
        [Output("signingCertificate")]
        public Output<string> SigningCertificate { get; private set; } = null!;

        /// <summary>
        /// The current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Date and time the `IdentityProvider` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;


        /// <summary>
        /// Create a IdentityProvider resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IdentityProvider(string name, IdentityProviderArgs args, CustomResourceOptions? options = null)
            : base("oci:Identity/identityProvider:IdentityProvider", name, args ?? new IdentityProviderArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IdentityProvider(string name, Input<string> id, IdentityProviderState? state = null, CustomResourceOptions? options = null)
            : base("oci:Identity/identityProvider:IdentityProvider", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing IdentityProvider resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IdentityProvider Get(string name, Input<string> id, IdentityProviderState? state = null, CustomResourceOptions? options = null)
        {
            return new IdentityProvider(name, id, state, options);
        }
    }

    public sealed class IdentityProviderArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of your tenancy.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Input("description", required: true)]
        public Input<string> Description { get; set; } = null!;

        [Input("freeformAttributes")]
        private InputMap<string>? _freeformAttributes;

        /// <summary>
        /// (Updatable) Extra name value pairs associated with this identity provider. Example: `{"clientId": "app_sf3kdjf3"}`
        /// </summary>
        public InputMap<string> FreeformAttributes
        {
            get => _freeformAttributes ?? (_freeformAttributes = new InputMap<string>());
            set => _freeformAttributes = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The XML that contains the information required for federating.
        /// </summary>
        [Input("metadata", required: true)]
        public Input<string> Metadata { get; set; } = null!;

        /// <summary>
        /// (Updatable) The URL for retrieving the identity provider's metadata, which contains information required for federating.
        /// </summary>
        [Input("metadataUrl", required: true)]
        public Input<string> MetadataUrl { get; set; } = null!;

        /// <summary>
        /// The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).  Example: `IDCS`
        /// </summary>
        [Input("productType", required: true)]
        public Input<string> ProductType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The protocol used for federation.  Example: `SAML2` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        public IdentityProviderArgs()
        {
        }
        public static new IdentityProviderArgs Empty => new IdentityProviderArgs();
    }

    public sealed class IdentityProviderState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of your tenancy.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The description you assign to the `IdentityProvider` during creation. Does not have to be unique, and it's changeable.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("freeformAttributes")]
        private InputMap<string>? _freeformAttributes;

        /// <summary>
        /// (Updatable) Extra name value pairs associated with this identity provider. Example: `{"clientId": "app_sf3kdjf3"}`
        /// </summary>
        public InputMap<string> FreeformAttributes
        {
            get => _freeformAttributes ?? (_freeformAttributes = new InputMap<string>());
            set => _freeformAttributes = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Input("inactiveState")]
        public Input<string>? InactiveState { get; set; }

        /// <summary>
        /// (Updatable) The XML that contains the information required for federating.
        /// </summary>
        [Input("metadata")]
        public Input<string>? Metadata { get; set; }

        /// <summary>
        /// (Updatable) The URL for retrieving the identity provider's metadata, which contains information required for federating.
        /// </summary>
        [Input("metadataUrl")]
        public Input<string>? MetadataUrl { get; set; }

        /// <summary>
        /// The name you assign to the `IdentityProvider` during creation. The name must be unique across all `IdentityProvider` objects in the tenancy and cannot be changed.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The identity provider service or product. Supported identity providers are Oracle Identity Cloud Service (IDCS) and Microsoft Active Directory Federation Services (ADFS).  Example: `IDCS`
        /// </summary>
        [Input("productType")]
        public Input<string>? ProductType { get; set; }

        /// <summary>
        /// (Updatable) The protocol used for federation.  Example: `SAML2` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("protocol")]
        public Input<string>? Protocol { get; set; }

        /// <summary>
        /// The URL to redirect federated users to for authentication with the identity provider.
        /// </summary>
        [Input("redirectUrl")]
        public Input<string>? RedirectUrl { get; set; }

        /// <summary>
        /// The identity provider's signing certificate used by the IAM Service to validate the SAML2 token.
        /// </summary>
        [Input("signingCertificate")]
        public Input<string>? SigningCertificate { get; set; }

        /// <summary>
        /// The current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Date and time the `IdentityProvider` was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        public IdentityProviderState()
        {
        }
        public static new IdentityProviderState Empty => new IdentityProviderState();
    }
}
