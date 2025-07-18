// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement
{
    /// <summary>
    /// This resource provides the Occm Demand Signal Item resource in Oracle Cloud Infrastructure Capacity Management service.
    /// 
    /// This API will create a demand signal item representing a resource request. This needs to be grouped under a demand signal.
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
    ///     var testOccmDemandSignalItem = new Oci.CapacityManagement.OccmDemandSignalItem("test_occm_demand_signal_item", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         DemandQuantity = occmDemandSignalItemDemandQuantity,
    ///         DemandSignalCatalogResourceId = testResource.Id,
    ///         DemandSignalId = testDemandSignal.Id,
    ///         Region = occmDemandSignalItemRegion,
    ///         RequestType = occmDemandSignalItemRequestType,
    ///         ResourceProperties = occmDemandSignalItemResourceProperties,
    ///         TimeNeededBefore = occmDemandSignalItemTimeNeededBefore,
    ///         AvailabilityDomain = occmDemandSignalItemAvailabilityDomain,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         Notes = occmDemandSignalItemNotes,
    ///         TargetCompartmentId = testCompartment.Id,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OccmDemandSignalItems can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem test_occm_demand_signal_item "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem")]
    public partial class OccmDemandSignalItem : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
        /// </summary>
        [Output("availabilityDomain")]
        public Output<string> AvailabilityDomain { get; private set; } = null!;

        /// <summary>
        /// The OCID of the tenancy from which the demand signal item was created.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The quantity of the resource that you want to demand from OCI.
        /// </summary>
        [Output("demandQuantity")]
        public Output<string> DemandQuantity { get; private set; } = null!;

        /// <summary>
        /// The OCID of the correponding demand signal catalog resource.
        /// </summary>
        [Output("demandSignalCatalogResourceId")]
        public Output<string> DemandSignalCatalogResourceId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the demand signal under which we need to create this item.
        /// </summary>
        [Output("demandSignalId")]
        public Output<string> DemandSignalId { get; private set; } = null!;

        /// <summary>
        /// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
        /// </summary>
        [Output("demandSignalNamespace")]
        public Output<string> DemandSignalNamespace { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
        /// 
        /// NOTE: The previous value gets overwritten with the new one for this once updated.
        /// </summary>
        [Output("notes")]
        public Output<string> Notes { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
        /// </summary>
        [Output("region")]
        public Output<string> Region { get; private set; } = null!;

        /// <summary>
        /// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
        /// </summary>
        [Output("requestType")]
        public Output<string> RequestType { get; private set; } = null!;

        /// <summary>
        /// The name of the Oracle Cloud Infrastructure resource that you want to request.
        /// </summary>
        [Output("resourceName")]
        public Output<string> ResourceName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
        /// </summary>
        [Output("resourceProperties")]
        public Output<ImmutableDictionary<string, string>> ResourceProperties { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
        /// </summary>
        [Output("targetCompartmentId")]
        public Output<string> TargetCompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("timeNeededBefore")]
        public Output<string> TimeNeededBefore { get; private set; } = null!;


        /// <summary>
        /// Create a OccmDemandSignalItem resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OccmDemandSignalItem(string name, OccmDemandSignalItemArgs args, CustomResourceOptions? options = null)
            : base("oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem", name, args ?? new OccmDemandSignalItemArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OccmDemandSignalItem(string name, Input<string> id, OccmDemandSignalItemState? state = null, CustomResourceOptions? options = null)
            : base("oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OccmDemandSignalItem resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OccmDemandSignalItem Get(string name, Input<string> id, OccmDemandSignalItemState? state = null, CustomResourceOptions? options = null)
        {
            return new OccmDemandSignalItem(name, id, state, options);
        }
    }

    public sealed class OccmDemandSignalItemArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the tenancy from which the demand signal item was created.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The quantity of the resource that you want to demand from OCI.
        /// </summary>
        [Input("demandQuantity", required: true)]
        public Input<string> DemandQuantity { get; set; } = null!;

        /// <summary>
        /// The OCID of the correponding demand signal catalog resource.
        /// </summary>
        [Input("demandSignalCatalogResourceId", required: true)]
        public Input<string> DemandSignalCatalogResourceId { get; set; } = null!;

        /// <summary>
        /// The OCID of the demand signal under which we need to create this item.
        /// </summary>
        [Input("demandSignalId", required: true)]
        public Input<string> DemandSignalId { get; set; } = null!;

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
        /// 
        /// NOTE: The previous value gets overwritten with the new one for this once updated.
        /// </summary>
        [Input("notes")]
        public Input<string>? Notes { get; set; }

        /// <summary>
        /// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
        /// </summary>
        [Input("region", required: true)]
        public Input<string> Region { get; set; } = null!;

        /// <summary>
        /// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
        /// </summary>
        [Input("requestType", required: true)]
        public Input<string> RequestType { get; set; } = null!;

        [Input("resourceProperties", required: true)]
        private InputMap<string>? _resourceProperties;

        /// <summary>
        /// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
        /// </summary>
        public InputMap<string> ResourceProperties
        {
            get => _resourceProperties ?? (_resourceProperties = new InputMap<string>());
            set => _resourceProperties = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
        /// </summary>
        [Input("targetCompartmentId")]
        public Input<string>? TargetCompartmentId { get; set; }

        /// <summary>
        /// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeNeededBefore", required: true)]
        public Input<string> TimeNeededBefore { get; set; } = null!;

        public OccmDemandSignalItemArgs()
        {
        }
        public static new OccmDemandSignalItemArgs Empty => new OccmDemandSignalItemArgs();
    }

    public sealed class OccmDemandSignalItemState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The OCID of the tenancy from which the demand signal item was created.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) The quantity of the resource that you want to demand from OCI.
        /// </summary>
        [Input("demandQuantity")]
        public Input<string>? DemandQuantity { get; set; }

        /// <summary>
        /// The OCID of the correponding demand signal catalog resource.
        /// </summary>
        [Input("demandSignalCatalogResourceId")]
        public Input<string>? DemandSignalCatalogResourceId { get; set; }

        /// <summary>
        /// The OCID of the demand signal under which we need to create this item.
        /// </summary>
        [Input("demandSignalId")]
        public Input<string>? DemandSignalId { get; set; }

        /// <summary>
        /// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
        /// </summary>
        [Input("demandSignalNamespace")]
        public Input<string>? DemandSignalNamespace { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
        /// 
        /// NOTE: The previous value gets overwritten with the new one for this once updated.
        /// </summary>
        [Input("notes")]
        public Input<string>? Notes { get; set; }

        /// <summary>
        /// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
        /// </summary>
        [Input("region")]
        public Input<string>? Region { get; set; }

        /// <summary>
        /// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
        /// </summary>
        [Input("requestType")]
        public Input<string>? RequestType { get; set; }

        /// <summary>
        /// The name of the Oracle Cloud Infrastructure resource that you want to request.
        /// </summary>
        [Input("resourceName")]
        public Input<string>? ResourceName { get; set; }

        [Input("resourceProperties")]
        private InputMap<string>? _resourceProperties;

        /// <summary>
        /// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
        /// </summary>
        public InputMap<string> ResourceProperties
        {
            get => _resourceProperties ?? (_resourceProperties = new InputMap<string>());
            set => _resourceProperties = value;
        }

        /// <summary>
        /// The current lifecycle state of the resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
        /// </summary>
        [Input("targetCompartmentId")]
        public Input<string>? TargetCompartmentId { get; set; }

        /// <summary>
        /// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("timeNeededBefore")]
        public Input<string>? TimeNeededBefore { get; set; }

        public OccmDemandSignalItemState()
        {
        }
        public static new OccmDemandSignalItemState Empty => new OccmDemandSignalItemState();
    }
}
