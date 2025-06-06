// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DemandSignal
{
    public static class GetOccDemandSignal
    {
        /// <summary>
        /// This data source provides details about a specific Occ Demand Signal resource in Oracle Cloud Infrastructure Demand Signal service.
        /// 
        /// Gets information about a OccDemandSignal.
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
        ///     var testOccDemandSignal = Oci.DemandSignal.GetOccDemandSignal.Invoke(new()
        ///     {
        ///         OccDemandSignalId = testOccDemandSignalOciDemandSignalOccDemandSignal.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOccDemandSignalResult> InvokeAsync(GetOccDemandSignalArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOccDemandSignalResult>("oci:DemandSignal/getOccDemandSignal:getOccDemandSignal", args ?? new GetOccDemandSignalArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Occ Demand Signal resource in Oracle Cloud Infrastructure Demand Signal service.
        /// 
        /// Gets information about a OccDemandSignal.
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
        ///     var testOccDemandSignal = Oci.DemandSignal.GetOccDemandSignal.Invoke(new()
        ///     {
        ///         OccDemandSignalId = testOccDemandSignalOciDemandSignalOccDemandSignal.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccDemandSignalResult> Invoke(GetOccDemandSignalInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccDemandSignalResult>("oci:DemandSignal/getOccDemandSignal:getOccDemandSignal", args ?? new GetOccDemandSignalInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Occ Demand Signal resource in Oracle Cloud Infrastructure Demand Signal service.
        /// 
        /// Gets information about a OccDemandSignal.
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
        ///     var testOccDemandSignal = Oci.DemandSignal.GetOccDemandSignal.Invoke(new()
        ///     {
        ///         OccDemandSignalId = testOccDemandSignalOciDemandSignalOccDemandSignal.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOccDemandSignalResult> Invoke(GetOccDemandSignalInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOccDemandSignalResult>("oci:DemandSignal/getOccDemandSignal:getOccDemandSignal", args ?? new GetOccDemandSignalInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOccDemandSignalArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OccDemandSignal.
        /// </summary>
        [Input("occDemandSignalId", required: true)]
        public string OccDemandSignalId { get; set; } = null!;

        public GetOccDemandSignalArgs()
        {
        }
        public static new GetOccDemandSignalArgs Empty => new GetOccDemandSignalArgs();
    }

    public sealed class GetOccDemandSignalInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OccDemandSignal.
        /// </summary>
        [Input("occDemandSignalId", required: true)]
        public Input<string> OccDemandSignalId { get; set; } = null!;

        public GetOccDemandSignalInvokeArgs()
        {
        }
        public static new GetOccDemandSignalInvokeArgs Empty => new GetOccDemandSignalInvokeArgs();
    }


    [OutputType]
    public sealed class GetOccDemandSignalResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the OccDemandSignal.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicator of whether to share the data with Oracle.
        /// </summary>
        public readonly bool IsActive;
        /// <summary>
        /// A message that describes the current state of the OccDemandSignal in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string OccDemandSignalId;
        /// <summary>
        /// The OccDemandSignal data.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccDemandSignalOccDemandSignalResult> OccDemandSignals;
        public readonly ImmutableArray<Outputs.GetOccDemandSignalPatchOperationResult> PatchOperations;
        /// <summary>
        /// The current state of the OccDemandSignal.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the OccDemandSignal was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the OccDemandSignal was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOccDemandSignalResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isActive,

            string lifecycleDetails,

            string occDemandSignalId,

            ImmutableArray<Outputs.GetOccDemandSignalOccDemandSignalResult> occDemandSignals,

            ImmutableArray<Outputs.GetOccDemandSignalPatchOperationResult> patchOperations,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsActive = isActive;
            LifecycleDetails = lifecycleDetails;
            OccDemandSignalId = occDemandSignalId;
            OccDemandSignals = occDemandSignals;
            PatchOperations = patchOperations;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
