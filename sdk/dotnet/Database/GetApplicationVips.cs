// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetApplicationVips
    {
        /// <summary>
        /// This data source provides the list of Application Vips in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of application virtual IP (VIP) addresses on a cloud VM cluster.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testApplicationVips = Oci.Database.GetApplicationVips.Invoke(new()
        ///     {
        ///         CloudVmClusterId = oci_database_cloud_vm_cluster.Test_cloud_vm_cluster.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         State = @var.Application_vip_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetApplicationVipsResult> InvokeAsync(GetApplicationVipsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetApplicationVipsResult>("oci:Database/getApplicationVips:getApplicationVips", args ?? new GetApplicationVipsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Application Vips in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of application virtual IP (VIP) addresses on a cloud VM cluster.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testApplicationVips = Oci.Database.GetApplicationVips.Invoke(new()
        ///     {
        ///         CloudVmClusterId = oci_database_cloud_vm_cluster.Test_cloud_vm_cluster.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         State = @var.Application_vip_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetApplicationVipsResult> Invoke(GetApplicationVipsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetApplicationVipsResult>("oci:Database/getApplicationVips:getApplicationVips", args ?? new GetApplicationVipsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetApplicationVipsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
        /// </summary>
        [Input("cloudVmClusterId", required: true)]
        public string CloudVmClusterId { get; set; } = null!;

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetApplicationVipsFilterArgs>? _filters;
        public List<Inputs.GetApplicationVipsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetApplicationVipsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetApplicationVipsArgs()
        {
        }
        public static new GetApplicationVipsArgs Empty => new GetApplicationVipsArgs();
    }

    public sealed class GetApplicationVipsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
        /// </summary>
        [Input("cloudVmClusterId", required: true)]
        public Input<string> CloudVmClusterId { get; set; } = null!;

        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetApplicationVipsFilterInputArgs>? _filters;
        public InputList<Inputs.GetApplicationVipsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetApplicationVipsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetApplicationVipsInvokeArgs()
        {
        }
        public static new GetApplicationVipsInvokeArgs Empty => new GetApplicationVipsInvokeArgs();
    }


    [OutputType]
    public sealed class GetApplicationVipsResult
    {
        /// <summary>
        /// The list of application_vips.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApplicationVipsApplicationVipResult> ApplicationVips;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud VM cluster associated with the application virtual IP (VIP) address.
        /// </summary>
        public readonly string CloudVmClusterId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetApplicationVipsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the application virtual IP (VIP) address.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetApplicationVipsResult(
            ImmutableArray<Outputs.GetApplicationVipsApplicationVipResult> applicationVips,

            string cloudVmClusterId,

            string compartmentId,

            ImmutableArray<Outputs.GetApplicationVipsFilterResult> filters,

            string id,

            string? state)
        {
            ApplicationVips = applicationVips;
            CloudVmClusterId = cloudVmClusterId;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}