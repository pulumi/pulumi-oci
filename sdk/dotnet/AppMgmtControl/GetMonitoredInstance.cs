// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AppMgmtControl
{
    public static class GetMonitoredInstance
    {
        /// <summary>
        /// This data source provides details about a specific Monitored Instance resource in Oracle Cloud Infrastructure Appmgmt Control service.
        /// 
        /// Gets a monitored instance by identifier
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
        ///         var testMonitoredInstance = Output.Create(Oci.AppMgmtControl.GetMonitoredInstance.InvokeAsync(new Oci.AppMgmtControl.GetMonitoredInstanceArgs
        ///         {
        ///             MonitoredInstanceId = oci_appmgmt_control_monitored_instance.Test_monitored_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMonitoredInstanceResult> InvokeAsync(GetMonitoredInstanceArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetMonitoredInstanceResult>("oci:AppMgmtControl/getMonitoredInstance:getMonitoredInstance", args ?? new GetMonitoredInstanceArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitored Instance resource in Oracle Cloud Infrastructure Appmgmt Control service.
        /// 
        /// Gets a monitored instance by identifier
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
        ///         var testMonitoredInstance = Output.Create(Oci.AppMgmtControl.GetMonitoredInstance.InvokeAsync(new Oci.AppMgmtControl.GetMonitoredInstanceArgs
        ///         {
        ///             MonitoredInstanceId = oci_appmgmt_control_monitored_instance.Test_monitored_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetMonitoredInstanceResult> Invoke(GetMonitoredInstanceInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetMonitoredInstanceResult>("oci:AppMgmtControl/getMonitoredInstance:getMonitoredInstance", args ?? new GetMonitoredInstanceInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMonitoredInstanceArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of monitored instance.
        /// </summary>
        [Input("monitoredInstanceId", required: true)]
        public string MonitoredInstanceId { get; set; } = null!;

        public GetMonitoredInstanceArgs()
        {
        }
    }

    public sealed class GetMonitoredInstanceInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// OCID of monitored instance.
        /// </summary>
        [Input("monitoredInstanceId", required: true)]
        public Input<string> MonitoredInstanceId { get; set; } = null!;

        public GetMonitoredInstanceInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetMonitoredInstanceResult
    {
        /// <summary>
        /// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name of the monitored instance. It is binded to [Compute Instance](https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/computeoverview.htm). DisplayName is fetched from [Core Service API](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/Instance/).
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of monitored instance.
        /// </summary>
        public readonly string InstanceId;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Management Agent Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Used to invoke manage operations on Management Agent Cloud Service.
        /// </summary>
        public readonly string ManagementAgentId;
        public readonly string MonitoredInstanceId;
        /// <summary>
        /// Monitoring status. Can be either enabled or disabled.
        /// </summary>
        public readonly string MonitoringState;
        /// <summary>
        /// The current state of the monitored instance.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the MonitoredInstance was created. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the MonitoredInstance was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMonitoredInstanceResult(
            string compartmentId,

            string displayName,

            string id,

            string instanceId,

            string lifecycleDetails,

            string managementAgentId,

            string monitoredInstanceId,

            string monitoringState,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Id = id;
            InstanceId = instanceId;
            LifecycleDetails = lifecycleDetails;
            ManagementAgentId = managementAgentId;
            MonitoredInstanceId = monitoredInstanceId;
            MonitoringState = monitoringState;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
