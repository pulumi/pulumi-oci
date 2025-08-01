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
    /// This resource provides the Internal Occm Demand Signal resource in Oracle Cloud Infrastructure Capacity Management service.
    /// 
    /// This is a internal PUT API which shall be used to update the metadata of the demand signal.
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
    ///     var testInternalOccmDemandSignal = new Oci.CapacityManagement.InternalOccmDemandSignal("test_internal_occm_demand_signal", new()
    ///     {
    ///         OccmDemandSignalId = testOccmDemandSignal.Id,
    ///         LifecycleDetails = internalOccmDemandSignalLifecycleDetails,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// InternalOccmDemandSignals can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal test_internal_occm_demand_signal "internal/occmDemandSignals/{occmDemandSignalId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal")]
    public partial class InternalOccmDemandSignal : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the tenancy from which the request to create the demand signal was made.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// A short description about the demand signal.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The display name of the demand signal.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The subset of demand signal states available for operators for updating the demand signal.
        /// 
        /// IN_PROGRESS &gt; Transitions the demand signal to IN_PROGRESS state. REJECTED &gt; Transitions the demand signal to REJECTED state. COMPLETED &gt; This will transition the demand signal to COMPLETED state.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The OCID of the customer group in which the demand signal is created.
        /// </summary>
        [Output("occCustomerGroupId")]
        public Output<string> OccCustomerGroupId { get; private set; } = null!;

        /// <summary>
        /// The OCID of the demand signal. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("occmDemandSignalId")]
        public Output<string> OccmDemandSignalId { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the demand signal.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The time when the demand signal was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The time when the demand signal was last updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a InternalOccmDemandSignal resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public InternalOccmDemandSignal(string name, InternalOccmDemandSignalArgs args, CustomResourceOptions? options = null)
            : base("oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal", name, args ?? new InternalOccmDemandSignalArgs(), MakeResourceOptions(options, ""))
        {
        }

        private InternalOccmDemandSignal(string name, Input<string> id, InternalOccmDemandSignalState? state = null, CustomResourceOptions? options = null)
            : base("oci:CapacityManagement/internalOccmDemandSignal:InternalOccmDemandSignal", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing InternalOccmDemandSignal resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static InternalOccmDemandSignal Get(string name, Input<string> id, InternalOccmDemandSignalState? state = null, CustomResourceOptions? options = null)
        {
            return new InternalOccmDemandSignal(name, id, state, options);
        }
    }

    public sealed class InternalOccmDemandSignalArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The subset of demand signal states available for operators for updating the demand signal.
        /// 
        /// IN_PROGRESS &gt; Transitions the demand signal to IN_PROGRESS state. REJECTED &gt; Transitions the demand signal to REJECTED state. COMPLETED &gt; This will transition the demand signal to COMPLETED state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the demand signal. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("occmDemandSignalId", required: true)]
        public Input<string> OccmDemandSignalId { get; set; } = null!;

        public InternalOccmDemandSignalArgs()
        {
        }
        public static new InternalOccmDemandSignalArgs Empty => new InternalOccmDemandSignalArgs();
    }

    public sealed class InternalOccmDemandSignalState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the tenancy from which the request to create the demand signal was made.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// A short description about the demand signal.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The display name of the demand signal.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The subset of demand signal states available for operators for updating the demand signal.
        /// 
        /// IN_PROGRESS &gt; Transitions the demand signal to IN_PROGRESS state. REJECTED &gt; Transitions the demand signal to REJECTED state. COMPLETED &gt; This will transition the demand signal to COMPLETED state.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The OCID of the customer group in which the demand signal is created.
        /// </summary>
        [Input("occCustomerGroupId")]
        public Input<string>? OccCustomerGroupId { get; set; }

        /// <summary>
        /// The OCID of the demand signal. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("occmDemandSignalId")]
        public Input<string>? OccmDemandSignalId { get; set; }

        /// <summary>
        /// The current lifecycle state of the demand signal.
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
        /// The time when the demand signal was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The time when the demand signal was last updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public InternalOccmDemandSignalState()
        {
        }
        public static new InternalOccmDemandSignalState Empty => new InternalOccmDemandSignalState();
    }
}
