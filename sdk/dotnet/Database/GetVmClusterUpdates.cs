// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusterUpdates
    {
        /// <summary>
        /// This data source provides the list of Vm Cluster Updates in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the maintenance updates that can be applied to the specified VM cluster. Applies to Exadata Cloud@Customer instances only.
        /// 
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
        ///     var testVmClusterUpdates = Oci.Database.GetVmClusterUpdates.Invoke(new()
        ///     {
        ///         VmClusterId = testVmCluster.Id,
        ///         State = vmClusterUpdateState,
        ///         UpdateType = vmClusterUpdateUpdateType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetVmClusterUpdatesResult> InvokeAsync(GetVmClusterUpdatesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetVmClusterUpdatesResult>("oci:Database/getVmClusterUpdates:getVmClusterUpdates", args ?? new GetVmClusterUpdatesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vm Cluster Updates in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the maintenance updates that can be applied to the specified VM cluster. Applies to Exadata Cloud@Customer instances only.
        /// 
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
        ///     var testVmClusterUpdates = Oci.Database.GetVmClusterUpdates.Invoke(new()
        ///     {
        ///         VmClusterId = testVmCluster.Id,
        ///         State = vmClusterUpdateState,
        ///         UpdateType = vmClusterUpdateUpdateType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVmClusterUpdatesResult> Invoke(GetVmClusterUpdatesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetVmClusterUpdatesResult>("oci:Database/getVmClusterUpdates:getVmClusterUpdates", args ?? new GetVmClusterUpdatesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vm Cluster Updates in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the maintenance updates that can be applied to the specified VM cluster. Applies to Exadata Cloud@Customer instances only.
        /// 
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
        ///     var testVmClusterUpdates = Oci.Database.GetVmClusterUpdates.Invoke(new()
        ///     {
        ///         VmClusterId = testVmCluster.Id,
        ///         State = vmClusterUpdateState,
        ///         UpdateType = vmClusterUpdateUpdateType,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVmClusterUpdatesResult> Invoke(GetVmClusterUpdatesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetVmClusterUpdatesResult>("oci:Database/getVmClusterUpdates:getVmClusterUpdates", args ?? new GetVmClusterUpdatesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVmClusterUpdatesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetVmClusterUpdatesFilterArgs>? _filters;
        public List<Inputs.GetVmClusterUpdatesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVmClusterUpdatesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given update type exactly.
        /// </summary>
        [Input("updateType")]
        public string? UpdateType { get; set; }

        /// <summary>
        /// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterId", required: true)]
        public string VmClusterId { get; set; } = null!;

        public GetVmClusterUpdatesArgs()
        {
        }
        public static new GetVmClusterUpdatesArgs Empty => new GetVmClusterUpdatesArgs();
    }

    public sealed class GetVmClusterUpdatesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetVmClusterUpdatesFilterInputArgs>? _filters;
        public InputList<Inputs.GetVmClusterUpdatesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVmClusterUpdatesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// A filter to return only resources that match the given update type exactly.
        /// </summary>
        [Input("updateType")]
        public Input<string>? UpdateType { get; set; }

        /// <summary>
        /// The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("vmClusterId", required: true)]
        public Input<string> VmClusterId { get; set; } = null!;

        public GetVmClusterUpdatesInvokeArgs()
        {
        }
        public static new GetVmClusterUpdatesInvokeArgs Empty => new GetVmClusterUpdatesInvokeArgs();
    }


    [OutputType]
    public sealed class GetVmClusterUpdatesResult
    {
        public readonly ImmutableArray<Outputs.GetVmClusterUpdatesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the maintenance update. Dependent on value of `lastAction`.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The type of VM cluster maintenance update.
        /// </summary>
        public readonly string? UpdateType;
        public readonly string VmClusterId;
        /// <summary>
        /// The list of vm_cluster_updates.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClusterUpdatesVmClusterUpdateResult> VmClusterUpdates;

        [OutputConstructor]
        private GetVmClusterUpdatesResult(
            ImmutableArray<Outputs.GetVmClusterUpdatesFilterResult> filters,

            string id,

            string? state,

            string? updateType,

            string vmClusterId,

            ImmutableArray<Outputs.GetVmClusterUpdatesVmClusterUpdateResult> vmClusterUpdates)
        {
            Filters = filters;
            Id = id;
            State = state;
            UpdateType = updateType;
            VmClusterId = vmClusterId;
            VmClusterUpdates = vmClusterUpdates;
        }
    }
}
