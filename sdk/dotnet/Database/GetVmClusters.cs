// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetVmClusters
    {
        /// <summary>
        /// This data source provides the list of Vm Clusters in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the VM clusters in the specified compartment. Applies to Exadata Cloud@Customer instances only.
        /// To list the cloud VM clusters in an Exadata Cloud Service instance, use the [ListCloudVmClusters ](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/ListCloudVmClusters) operation.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testVmClusters = Oci.Database.GetVmClusters.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Vm_cluster_display_name,
        ///         ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///         State = @var.Vm_cluster_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVmClustersResult> InvokeAsync(GetVmClustersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVmClustersResult>("oci:Database/getVmClusters:getVmClusters", args ?? new GetVmClustersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vm Clusters in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the VM clusters in the specified compartment. Applies to Exadata Cloud@Customer instances only.
        /// To list the cloud VM clusters in an Exadata Cloud Service instance, use the [ListCloudVmClusters ](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/ListCloudVmClusters) operation.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testVmClusters = Oci.Database.GetVmClusters.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Vm_cluster_display_name,
        ///         ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///         State = @var.Vm_cluster_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetVmClustersResult> Invoke(GetVmClustersInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVmClustersResult>("oci:Database/getVmClusters:getVmClusters", args ?? new GetVmClustersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVmClustersArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// If provided, filters the results for the given Exadata Infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId")]
        public string? ExadataInfrastructureId { get; set; }

        [Input("filters")]
        private List<Inputs.GetVmClustersFilterArgs>? _filters;
        public List<Inputs.GetVmClustersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVmClustersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetVmClustersArgs()
        {
        }
        public static new GetVmClustersArgs Empty => new GetVmClustersArgs();
    }

    public sealed class GetVmClustersInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// If provided, filters the results for the given Exadata Infrastructure.
        /// </summary>
        [Input("exadataInfrastructureId")]
        public Input<string>? ExadataInfrastructureId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetVmClustersFilterInputArgs>? _filters;
        public InputList<Inputs.GetVmClustersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVmClustersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetVmClustersInvokeArgs()
        {
        }
        public static new GetVmClustersInvokeArgs Empty => new GetVmClustersInvokeArgs();
    }


    [OutputType]
    public sealed class GetVmClustersResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        public readonly string? ExadataInfrastructureId;
        public readonly ImmutableArray<Outputs.GetVmClustersFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the VM cluster.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of vm_clusters.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVmClustersVmClusterResult> VmClusters;

        [OutputConstructor]
        private GetVmClustersResult(
            string compartmentId,

            string? displayName,

            string? exadataInfrastructureId,

            ImmutableArray<Outputs.GetVmClustersFilterResult> filters,

            string id,

            string? state,

            ImmutableArray<Outputs.GetVmClustersVmClusterResult> vmClusters)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            ExadataInfrastructureId = exadataInfrastructureId;
            Filters = filters;
            Id = id;
            State = state;
            VmClusters = vmClusters;
        }
    }
}