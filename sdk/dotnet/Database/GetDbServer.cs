// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDbServer
    {
        /// <summary>
        /// This data source provides details about a specific Db Server resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the Exadata Db server.
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
        ///         var testDbServer = Output.Create(Oci.Database.GetDbServer.InvokeAsync(new Oci.Database.GetDbServerArgs
        ///         {
        ///             DbServerId = oci_database_db_server.Test_db_server.Id,
        ///             ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDbServerResult> InvokeAsync(GetDbServerArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDbServerResult>("oci:Database/getDbServer:getDbServer", args ?? new GetDbServerArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db Server resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets information about the Exadata Db server.
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
        ///         var testDbServer = Output.Create(Oci.Database.GetDbServer.InvokeAsync(new Oci.Database.GetDbServerArgs
        ///         {
        ///             DbServerId = oci_database_db_server.Test_db_server.Id,
        ///             ExadataInfrastructureId = oci_database_exadata_infrastructure.Test_exadata_infrastructure.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDbServerResult> Invoke(GetDbServerInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDbServerResult>("oci:Database/getDbServer:getDbServer", args ?? new GetDbServerInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbServerArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The DB server [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbServerId", required: true)]
        public string DbServerId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public string ExadataInfrastructureId { get; set; } = null!;

        public GetDbServerArgs()
        {
        }
    }

    public sealed class GetDbServerInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The DB server [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbServerId", required: true)]
        public Input<string> DbServerId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ExadataInfrastructure.
        /// </summary>
        [Input("exadataInfrastructureId", required: true)]
        public Input<string> ExadataInfrastructureId { get; set; } = null!;

        public GetDbServerInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetDbServerResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The number of CPU cores enabled on the Db server.
        /// </summary>
        public readonly int CpuCoreCount;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Db nodes associated with the Db server.
        /// </summary>
        public readonly ImmutableArray<string> DbNodeIds;
        /// <summary>
        /// The allocated local node storage in GBs on the Db server.
        /// </summary>
        public readonly int DbNodeStorageSizeInGbs;
        public readonly string DbServerId;
        /// <summary>
        /// The scheduling details for the quarterly maintenance window. Patching and system updates take place during the maintenance window.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDbServerDbServerPatchingDetailResult> DbServerPatchingDetails;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The user-friendly name for the Db server. The name does not need to be unique.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
        /// </summary>
        public readonly string ExadataInfrastructureId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The total number of CPU cores available.
        /// </summary>
        public readonly int MaxCpuCount;
        /// <summary>
        /// The total local node storage available in GBs.
        /// </summary>
        public readonly int MaxDbNodeStorageInGbs;
        /// <summary>
        /// The total memory available in GBs.
        /// </summary>
        public readonly int MaxMemoryInGbs;
        /// <summary>
        /// The allocated memory in GBs on the Db server.
        /// </summary>
        public readonly int MemorySizeInGbs;
        /// <summary>
        /// The current state of the Db server.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time that the Db Server was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM Clusters associated with the Db server.
        /// </summary>
        public readonly ImmutableArray<string> VmClusterIds;

        [OutputConstructor]
        private GetDbServerResult(
            string compartmentId,

            int cpuCoreCount,

            ImmutableArray<string> dbNodeIds,

            int dbNodeStorageSizeInGbs,

            string dbServerId,

            ImmutableArray<Outputs.GetDbServerDbServerPatchingDetailResult> dbServerPatchingDetails,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string exadataInfrastructureId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string lifecycleDetails,

            int maxCpuCount,

            int maxDbNodeStorageInGbs,

            int maxMemoryInGbs,

            int memorySizeInGbs,

            string state,

            string timeCreated,

            ImmutableArray<string> vmClusterIds)
        {
            CompartmentId = compartmentId;
            CpuCoreCount = cpuCoreCount;
            DbNodeIds = dbNodeIds;
            DbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            DbServerId = dbServerId;
            DbServerPatchingDetails = dbServerPatchingDetails;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExadataInfrastructureId = exadataInfrastructureId;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            MaxCpuCount = maxCpuCount;
            MaxDbNodeStorageInGbs = maxDbNodeStorageInGbs;
            MaxMemoryInGbs = maxMemoryInGbs;
            MemorySizeInGbs = memorySizeInGbs;
            State = state;
            TimeCreated = timeCreated;
            VmClusterIds = vmClusterIds;
        }
    }
}
