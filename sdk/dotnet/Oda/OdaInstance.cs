// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda
{
    /// <summary>
    /// This resource provides the Oda Instance resource in Oracle Cloud Infrastructure Digital Assistant service.
    /// 
    /// Starts an asynchronous job to create a Digital Assistant instance.
    /// 
    /// To monitor the status of the job, take the `opc-work-request-id` response
    /// header value and use it to call `GET /workRequests/{workRequestId}`.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testOdaInstance = new Oci.Oda.OdaInstance("testOdaInstance", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         ShapeName = "DEVELOPMENT",
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = @var.Oda_instance_description,
    ///         DisplayName = @var.Oda_instance_display_name,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IdentityDomain = @var.Oda_instance_identity_domain,
    ///         IsRoleBasedAccess = @var.Oda_instance_is_role_based_access,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OdaInstances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Oda/odaInstance:OdaInstance test_oda_instance "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Oda/odaInstance:OdaInstance")]
    public partial class OdaInstance : global::Pulumi.CustomResource
    {
        /// <summary>
        /// A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
        /// </summary>
        [Output("attachmentIds")]
        public Output<ImmutableArray<string>> AttachmentIds { get; private set; } = null!;

        /// <summary>
        /// A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
        /// </summary>
        [Output("attachmentTypes")]
        public Output<ImmutableArray<string>> AttachmentTypes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Identifier of the compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// URL for the connector's endpoint.
        /// </summary>
        [Output("connectorUrl")]
        public Output<string> ConnectorUrl { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of the Digital Assistant instance.
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
        /// </summary>
        [Output("identityAppConsoleUrl")]
        public Output<string> IdentityAppConsoleUrl { get; private set; } = null!;

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
        /// </summary>
        [Output("identityAppGuid")]
        public Output<string> IdentityAppGuid { get; private set; } = null!;

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
        /// </summary>
        [Output("identityDomain")]
        public Output<string> IdentityDomain { get; private set; } = null!;

        /// <summary>
        /// A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
        /// </summary>
        [Output("importedPackageIds")]
        public Output<ImmutableArray<string>> ImportedPackageIds { get; private set; } = null!;

        /// <summary>
        /// A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
        /// </summary>
        [Output("importedPackageNames")]
        public Output<ImmutableArray<string>> ImportedPackageNames { get; private set; } = null!;

        /// <summary>
        /// Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
        /// </summary>
        [Output("isRoleBasedAccess")]
        public Output<bool> IsRoleBasedAccess { get; private set; } = null!;

        /// <summary>
        /// The current sub-state of the Digital Assistant instance.
        /// </summary>
        [Output("lifecycleSubState")]
        public Output<string> LifecycleSubState { get; private set; } = null!;

        /// <summary>
        /// A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
        /// </summary>
        [Output("restrictedOperations")]
        public Output<ImmutableArray<Outputs.OdaInstanceRestrictedOperation>> RestrictedOperations { get; private set; } = null!;

        /// <summary>
        /// Shape or size of the instance.
        /// </summary>
        [Output("shapeName")]
        public Output<string> ShapeName { get; private set; } = null!;

        /// <summary>
        /// The current state of the Digital Assistant instance.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
        /// </summary>
        [Output("stateMessage")]
        public Output<string> StateMessage { get; private set; } = null!;

        /// <summary>
        /// When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// URL for the Digital Assistant web application that's associated with the instance.
        /// </summary>
        [Output("webAppUrl")]
        public Output<string> WebAppUrl { get; private set; } = null!;


        /// <summary>
        /// Create a OdaInstance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OdaInstance(string name, OdaInstanceArgs args, CustomResourceOptions? options = null)
            : base("oci:Oda/odaInstance:OdaInstance", name, args ?? new OdaInstanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OdaInstance(string name, Input<string> id, OdaInstanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:Oda/odaInstance:OdaInstance", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OdaInstance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OdaInstance Get(string name, Input<string> id, OdaInstanceState? state = null, CustomResourceOptions? options = null)
        {
            return new OdaInstance(name, id, state, options);
        }
    }

    public sealed class OdaInstanceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Identifier of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Digital Assistant instance.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
        /// </summary>
        [Input("identityDomain")]
        public Input<string>? IdentityDomain { get; set; }

        /// <summary>
        /// Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
        /// </summary>
        [Input("isRoleBasedAccess")]
        public Input<bool>? IsRoleBasedAccess { get; set; }

        /// <summary>
        /// Shape or size of the instance.
        /// </summary>
        [Input("shapeName", required: true)]
        public Input<string> ShapeName { get; set; } = null!;

        /// <summary>
        /// The current state of the Digital Assistant instance.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public OdaInstanceArgs()
        {
        }
        public static new OdaInstanceArgs Empty => new OdaInstanceArgs();
    }

    public sealed class OdaInstanceState : global::Pulumi.ResourceArgs
    {
        [Input("attachmentIds")]
        private InputList<string>? _attachmentIds;

        /// <summary>
        /// A list of attachment identifiers for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
        /// </summary>
        public InputList<string> AttachmentIds
        {
            get => _attachmentIds ?? (_attachmentIds = new InputList<string>());
            set => _attachmentIds = value;
        }

        [Input("attachmentTypes")]
        private InputList<string>? _attachmentTypes;

        /// <summary>
        /// A list of attachment types for this instance (if any). Use attachmentIds to get the details of the attachments.
        /// </summary>
        public InputList<string> AttachmentTypes
        {
            get => _attachmentTypes ?? (_attachmentTypes = new InputList<string>());
            set => _attachmentTypes = value;
        }

        /// <summary>
        /// (Updatable) Identifier of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// URL for the connector's endpoint.
        /// </summary>
        [Input("connectorUrl")]
        public Input<string>? ConnectorUrl { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Digital Assistant instance.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the URL for the administration console used to manage the Identity Application instance Digital Assistant has created inside the user-specified identity domain.
        /// </summary>
        [Input("identityAppConsoleUrl")]
        public Input<string>? IdentityAppConsoleUrl { get; set; }

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the GUID of the Identity Application instance Digital Assistant has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this Digital Assistant instance for users within the identity domain.
        /// </summary>
        [Input("identityAppGuid")]
        public Input<string>? IdentityAppGuid { get; set; }

        /// <summary>
        /// If isRoleBasedAccess is set to true, this property specifies the identity domain that is to be used to implement this type of authorzation. Digital Assistant will create an Identity Application instance and Application Roles within this identity domain. The caller may then perform and user roll mappings they like to grant access to users within the identity domain.
        /// </summary>
        [Input("identityDomain")]
        public Input<string>? IdentityDomain { get; set; }

        [Input("importedPackageIds")]
        private InputList<string>? _importedPackageIds;

        /// <summary>
        /// A list of package ids imported into this instance (if any). Use GetImportedPackage to get the details of the imported packages.
        /// </summary>
        public InputList<string> ImportedPackageIds
        {
            get => _importedPackageIds ?? (_importedPackageIds = new InputList<string>());
            set => _importedPackageIds = value;
        }

        [Input("importedPackageNames")]
        private InputList<string>? _importedPackageNames;

        /// <summary>
        /// A list of package names imported into this instance (if any). Use importedPackageIds field to get the details of the imported packages.
        /// </summary>
        public InputList<string> ImportedPackageNames
        {
            get => _importedPackageNames ?? (_importedPackageNames = new InputList<string>());
            set => _importedPackageNames = value;
        }

        /// <summary>
        /// Should this Digital Assistant instance use role-based authorization via an identity domain (true) or use the default policy-based authorization via IAM policies (false)
        /// </summary>
        [Input("isRoleBasedAccess")]
        public Input<bool>? IsRoleBasedAccess { get; set; }

        /// <summary>
        /// The current sub-state of the Digital Assistant instance.
        /// </summary>
        [Input("lifecycleSubState")]
        public Input<string>? LifecycleSubState { get; set; }

        [Input("restrictedOperations")]
        private InputList<Inputs.OdaInstanceRestrictedOperationGetArgs>? _restrictedOperations;

        /// <summary>
        /// A list of restricted operations (across all attachments) for this instance (if any). Use GetOdaInstanceAttachment to get the details of the attachments.
        /// </summary>
        public InputList<Inputs.OdaInstanceRestrictedOperationGetArgs> RestrictedOperations
        {
            get => _restrictedOperations ?? (_restrictedOperations = new InputList<Inputs.OdaInstanceRestrictedOperationGetArgs>());
            set => _restrictedOperations = value;
        }

        /// <summary>
        /// Shape or size of the instance.
        /// </summary>
        [Input("shapeName")]
        public Input<string>? ShapeName { get; set; }

        /// <summary>
        /// The current state of the Digital Assistant instance.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// A message that describes the current state in more detail. For example, actionable information about an instance that's in the `FAILED` state.
        /// </summary>
        [Input("stateMessage")]
        public Input<string>? StateMessage { get; set; }

        /// <summary>
        /// When the Digital Assistant instance was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// When the Digital Assistance instance was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// URL for the Digital Assistant web application that's associated with the instance.
        /// </summary>
        [Input("webAppUrl")]
        public Input<string>? WebAppUrl { get; set; }

        public OdaInstanceState()
        {
        }
        public static new OdaInstanceState Empty => new OdaInstanceState();
    }
}