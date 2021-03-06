// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVolumeGroupReplicas
    {
        /// <summary>
        /// This data source provides the list of Volume Group Replicas in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume group replicas in the specified compartment. You can filter the results by volume group.
        /// For more information, see [Volume Group Replication](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroupreplication.htm).
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testVolumeGroupReplicas = Output.Create(Oci.Core.GetVolumeGroupReplicas.InvokeAsync(new Oci.Core.GetVolumeGroupReplicasArgs
        ///         {
        ///             AvailabilityDomain = @var.Volume_group_replica_availability_domain,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Volume_group_replica_display_name,
        ///             State = @var.Volume_group_replica_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVolumeGroupReplicasResult> InvokeAsync(GetVolumeGroupReplicasArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVolumeGroupReplicasResult>("oci:Core/getVolumeGroupReplicas:getVolumeGroupReplicas", args ?? new GetVolumeGroupReplicasArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Volume Group Replicas in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the volume group replicas in the specified compartment. You can filter the results by volume group.
        /// For more information, see [Volume Group Replication](https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroupreplication.htm).
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testVolumeGroupReplicas = Output.Create(Oci.Core.GetVolumeGroupReplicas.InvokeAsync(new Oci.Core.GetVolumeGroupReplicasArgs
        ///         {
        ///             AvailabilityDomain = @var.Volume_group_replica_availability_domain,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Volume_group_replica_display_name,
        ///             State = @var.Volume_group_replica_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetVolumeGroupReplicasResult> Invoke(GetVolumeGroupReplicasInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVolumeGroupReplicasResult>("oci:Core/getVolumeGroupReplicas:getVolumeGroupReplicas", args ?? new GetVolumeGroupReplicasInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVolumeGroupReplicasArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public string AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetVolumeGroupReplicasFilterArgs>? _filters;
        public List<Inputs.GetVolumeGroupReplicasFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVolumeGroupReplicasFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetVolumeGroupReplicasArgs()
        {
        }
    }

    public sealed class GetVolumeGroupReplicasInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain", required: true)]
        public Input<string> AvailabilityDomain { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetVolumeGroupReplicasFilterInputArgs>? _filters;
        public InputList<Inputs.GetVolumeGroupReplicasFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVolumeGroupReplicasFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetVolumeGroupReplicasInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetVolumeGroupReplicasResult
    {
        /// <summary>
        /// The availability domain of the volume group replica.
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment that contains the volume group replica.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVolumeGroupReplicasFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of a volume group.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of volume_group_replicas.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVolumeGroupReplicasVolumeGroupReplicaResult> VolumeGroupReplicas;

        [OutputConstructor]
        private GetVolumeGroupReplicasResult(
            string availabilityDomain,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVolumeGroupReplicasFilterResult> filters,

            string id,

            string? state,

            ImmutableArray<Outputs.GetVolumeGroupReplicasVolumeGroupReplicaResult> volumeGroupReplicas)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VolumeGroupReplicas = volumeGroupReplicas;
        }
    }
}
