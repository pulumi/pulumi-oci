// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetFleetBlocklists
    {
        /// <summary>
        /// This data source provides the list of Fleet Blocklists in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of blocklist entities contained by a fleet.
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
        ///         var testFleetBlocklists = Output.Create(Oci.Jms.GetFleetBlocklists.InvokeAsync(new Oci.Jms.GetFleetBlocklistsArgs
        ///         {
        ///             FleetId = oci_jms_fleet.Test_fleet.Id,
        ///             ManagedInstanceId = oci_osmanagement_managed_instance.Test_managed_instance.Id,
        ///             Operation = @var.Fleet_blocklist_operation,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFleetBlocklistsResult> InvokeAsync(GetFleetBlocklistsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFleetBlocklistsResult>("oci:Jms/getFleetBlocklists:getFleetBlocklists", args ?? new GetFleetBlocklistsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fleet Blocklists in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of blocklist entities contained by a fleet.
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
        ///         var testFleetBlocklists = Output.Create(Oci.Jms.GetFleetBlocklists.InvokeAsync(new Oci.Jms.GetFleetBlocklistsArgs
        ///         {
        ///             FleetId = oci_jms_fleet.Test_fleet.Id,
        ///             ManagedInstanceId = oci_osmanagement_managed_instance.Test_managed_instance.Id,
        ///             Operation = @var.Fleet_blocklist_operation,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFleetBlocklistsResult> Invoke(GetFleetBlocklistsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetFleetBlocklistsResult>("oci:Jms/getFleetBlocklists:getFleetBlocklists", args ?? new GetFleetBlocklistsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFleetBlocklistsArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetFleetBlocklistsFilterArgs>? _filters;
        public List<Inputs.GetFleetBlocklistsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFleetBlocklistsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public string FleetId { get; set; } = null!;

        /// <summary>
        /// The Fleet-unique identifier of the related managed instance.
        /// </summary>
        [Input("managedInstanceId")]
        public string? ManagedInstanceId { get; set; }

        /// <summary>
        /// The operation type.
        /// </summary>
        [Input("operation")]
        public string? Operation { get; set; }

        public GetFleetBlocklistsArgs()
        {
        }
    }

    public sealed class GetFleetBlocklistsInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetFleetBlocklistsFilterInputArgs>? _filters;
        public InputList<Inputs.GetFleetBlocklistsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFleetBlocklistsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
        /// </summary>
        [Input("fleetId", required: true)]
        public Input<string> FleetId { get; set; } = null!;

        /// <summary>
        /// The Fleet-unique identifier of the related managed instance.
        /// </summary>
        [Input("managedInstanceId")]
        public Input<string>? ManagedInstanceId { get; set; }

        /// <summary>
        /// The operation type.
        /// </summary>
        [Input("operation")]
        public Input<string>? Operation { get; set; }

        public GetFleetBlocklistsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetFleetBlocklistsResult
    {
        public readonly ImmutableArray<Outputs.GetFleetBlocklistsFilterResult> Filters;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the fleet.
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The blocklist
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetBlocklistsItemResult> Items;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance.
        /// </summary>
        public readonly string? ManagedInstanceId;
        /// <summary>
        /// The operation type
        /// </summary>
        public readonly string? Operation;

        [OutputConstructor]
        private GetFleetBlocklistsResult(
            ImmutableArray<Outputs.GetFleetBlocklistsFilterResult> filters,

            string fleetId,

            string id,

            ImmutableArray<Outputs.GetFleetBlocklistsItemResult> items,

            string? managedInstanceId,

            string? operation)
        {
            Filters = filters;
            FleetId = fleetId;
            Id = id;
            Items = items;
            ManagedInstanceId = managedInstanceId;
            Operation = operation;
        }
    }
}
