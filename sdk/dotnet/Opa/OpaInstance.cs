// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opa
{
    /// <summary>
    /// This resource provides the Opa Instance resource in Oracle Cloud Infrastructure Opa service.
    /// 
    /// Creates a new OpaInstance.
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
    ///     var testOpaInstance = new Oci.Opa.OpaInstance("testOpaInstance", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         DisplayName = @var.Opa_instance_display_name,
    ///         ShapeName = oci_core_shape.Test_shape.Name,
    ///         ConsumptionModel = @var.Opa_instance_consumption_model,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = @var.Opa_instance_description,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IdcsAt = @var.Opa_instance_idcs_at,
    ///         IsBreakglassEnabled = @var.Opa_instance_is_breakglass_enabled,
    ///         MeteringType = @var.Opa_instance_metering_type,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OpaInstances can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Opa/opaInstance:OpaInstance test_opa_instance "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Opa/opaInstance:OpaInstance")]
    public partial class OpaInstance : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Parameter specifying which entitlement to use for billing purposes
        /// </summary>
        [Output("consumptionModel")]
        public Output<string> ConsumptionModel { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Description of the Oracle Process Automation instance.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
        /// </summary>
        [Output("idcsAt")]
        public Output<string> IdcsAt { get; private set; } = null!;

        /// <summary>
        /// This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Output("identityAppDisplayName")]
        public Output<string> IdentityAppDisplayName { get; private set; } = null!;

        /// <summary>
        /// This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Output("identityAppGuid")]
        public Output<string> IdentityAppGuid { get; private set; } = null!;

        /// <summary>
        /// This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Output("identityAppOpcServiceInstanceGuid")]
        public Output<string> IdentityAppOpcServiceInstanceGuid { get; private set; } = null!;

        /// <summary>
        /// This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Output("identityDomainUrl")]
        public Output<string> IdentityDomainUrl { get; private set; } = null!;

        /// <summary>
        /// OPA Instance URL
        /// </summary>
        [Output("instanceUrl")]
        public Output<string> InstanceUrl { get; private set; } = null!;

        /// <summary>
        /// indicates if breakGlass is enabled for the opa instance.
        /// </summary>
        [Output("isBreakglassEnabled")]
        public Output<bool> IsBreakglassEnabled { get; private set; } = null!;

        /// <summary>
        /// MeteringType Identifier
        /// </summary>
        [Output("meteringType")]
        public Output<string> MeteringType { get; private set; } = null!;

        /// <summary>
        /// Shape of the instance.
        /// </summary>
        [Output("shapeName")]
        public Output<string> ShapeName { get; private set; } = null!;

        /// <summary>
        /// The current state of the OpaInstance.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, object>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when OpaInstance was created. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time the OpaInstance was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a OpaInstance resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OpaInstance(string name, OpaInstanceArgs args, CustomResourceOptions? options = null)
            : base("oci:Opa/opaInstance:OpaInstance", name, args ?? new OpaInstanceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OpaInstance(string name, Input<string> id, OpaInstanceState? state = null, CustomResourceOptions? options = null)
            : base("oci:Opa/opaInstance:OpaInstance", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OpaInstance resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OpaInstance Get(string name, Input<string> id, OpaInstanceState? state = null, CustomResourceOptions? options = null)
        {
            return new OpaInstance(name, id, state, options);
        }
    }

    public sealed class OpaInstanceArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Parameter specifying which entitlement to use for billing purposes
        /// </summary>
        [Input("consumptionModel")]
        public Input<string>? ConsumptionModel { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Oracle Process Automation instance.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
        /// </summary>
        [Input("idcsAt")]
        public Input<string>? IdcsAt { get; set; }

        /// <summary>
        /// indicates if breakGlass is enabled for the opa instance.
        /// </summary>
        [Input("isBreakglassEnabled")]
        public Input<bool>? IsBreakglassEnabled { get; set; }

        /// <summary>
        /// MeteringType Identifier
        /// </summary>
        [Input("meteringType")]
        public Input<string>? MeteringType { get; set; }

        /// <summary>
        /// Shape of the instance.
        /// </summary>
        [Input("shapeName", required: true)]
        public Input<string> ShapeName { get; set; } = null!;

        public OpaInstanceArgs()
        {
        }
        public static new OpaInstanceArgs Empty => new OpaInstanceArgs();
    }

    public sealed class OpaInstanceState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Compartment Identifier
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Parameter specifying which entitlement to use for billing purposes
        /// </summary>
        [Input("consumptionModel")]
        public Input<string>? ConsumptionModel { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) Description of the Oracle Process Automation instance.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) OpaInstance Identifier. User-friendly name for the instance. Avoid entering confidential information. You can change this value anytime.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// IDCS Authentication token. This is required for all realms with IDCS. This property is optional, as it is not required for non-IDCS realms.
        /// </summary>
        [Input("idcsAt")]
        public Input<string>? IdcsAt { get; set; }

        /// <summary>
        /// This property specifies the name of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Input("identityAppDisplayName")]
        public Input<string>? IdentityAppDisplayName { get; set; }

        /// <summary>
        /// This property specifies the GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user role mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Input("identityAppGuid")]
        public Input<string>? IdentityAppGuid { get; set; }

        /// <summary>
        /// This property specifies the OPC Service Instance GUID of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Input("identityAppOpcServiceInstanceGuid")]
        public Input<string>? IdentityAppOpcServiceInstanceGuid { get; set; }

        /// <summary>
        /// This property specifies the domain url of the Identity Application instance OPA has created inside the user-specified identity domain. This identity application instance may be used to host user roll mappings to grant access to this OPA instance for users within the identity domain.
        /// </summary>
        [Input("identityDomainUrl")]
        public Input<string>? IdentityDomainUrl { get; set; }

        /// <summary>
        /// OPA Instance URL
        /// </summary>
        [Input("instanceUrl")]
        public Input<string>? InstanceUrl { get; set; }

        /// <summary>
        /// indicates if breakGlass is enabled for the opa instance.
        /// </summary>
        [Input("isBreakglassEnabled")]
        public Input<bool>? IsBreakglassEnabled { get; set; }

        /// <summary>
        /// MeteringType Identifier
        /// </summary>
        [Input("meteringType")]
        public Input<string>? MeteringType { get; set; }

        /// <summary>
        /// Shape of the instance.
        /// </summary>
        [Input("shapeName")]
        public Input<string>? ShapeName { get; set; }

        /// <summary>
        /// The current state of the OpaInstance.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<object>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<object> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<object>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The time when OpaInstance was created. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time the OpaInstance was updated. An RFC3339 formatted datetime string
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public OpaInstanceState()
        {
        }
        public static new OpaInstanceState Empty => new OpaInstanceState();
    }
}