// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetFleet
    {
        /// <summary>
        /// This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Retrieve a Fleet with the specified identifier.
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
        ///         var testFleet = Output.Create(Oci.Jms.GetFleet.InvokeAsync(new Oci.Jms.GetFleetArgs
        ///         {
        ///             FleetId = oci_jms_fleet.Test_fleet.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFleetResult> InvokeAsync(GetFleetArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFleetResult>("oci:Jms/getFleet:getFleet", args ?? new GetFleetArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fleet resource in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Retrieve a Fleet with the specified identifier.
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
        ///         var testFleet = Output.Create(Oci.Jms.GetFleet.InvokeAsync(new Oci.Jms.GetFleetArgs
        ///         {
        ///             FleetId = oci_jms_fleet.Test_fleet.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFleetResult> Invoke(GetFleetInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetFleetResult>("oci:Jms/getFleet:getFleet", args ?? new GetFleetInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFleetArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public string FleetId { get; set; } = null!;

        public GetFleetArgs()
        {
        }
    }

    public sealed class GetFleetInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public Input<string> FleetId { get; set; } = null!;

        public GetFleetInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetFleetResult
    {
        /// <summary>
        /// The approximate count of all unique applications in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        public readonly int ApproximateApplicationCount;
        /// <summary>
        /// The approximate count of all unique Java installations in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        public readonly int ApproximateInstallationCount;
        /// <summary>
        /// The approximate count of all unique Java Runtimes in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        public readonly int ApproximateJreCount;
        /// <summary>
        /// The approximate count of all unique managed instances in the Fleet in the past seven days. This metric is provided on a best-effort manner, and is not taken into account when computing the resource ETag.
        /// </summary>
        public readonly int ApproximateManagedInstanceCount;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of the Fleet.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. (See [Understanding Free-form Tags](https://docs.cloud.oracle.com/iaas/Content/Tagging/Tasks/managingtagsandtagnamespaces.htm)).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// The Fleet's description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The name of the Fleet.
        /// </summary>
        public readonly string DisplayName;
        public readonly string FleetId;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`. (See [Managing Tags and Tag Namespaces](https://docs.cloud.oracle.com/iaas/Content/Tagging/Concepts/understandingfreeformtags.htm).)
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Custom Log for inventory or operation log.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetInventoryLogResult> InventoryLogs;
        /// <summary>
        /// Custom Log for inventory or operation log.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetOperationLogResult> OperationLogs;
        /// <summary>
        /// The lifecycle state of the Fleet.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The creation date and time of the Fleet (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetFleetResult(
            int approximateApplicationCount,

            int approximateInstallationCount,

            int approximateJreCount,

            int approximateManagedInstanceCount,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            string fleetId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetFleetInventoryLogResult> inventoryLogs,

            ImmutableArray<Outputs.GetFleetOperationLogResult> operationLogs,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated)
        {
            ApproximateApplicationCount = approximateApplicationCount;
            ApproximateInstallationCount = approximateInstallationCount;
            ApproximateJreCount = approximateJreCount;
            ApproximateManagedInstanceCount = approximateManagedInstanceCount;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FleetId = fleetId;
            FreeformTags = freeformTags;
            Id = id;
            InventoryLogs = inventoryLogs;
            OperationLogs = operationLogs;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
        }
    }
}
