// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVcns
    {
        /// <summary>
        /// This data source provides the list of Vcns in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the virtual cloud networks (VCNs) in the specified compartment.
        /// 
        /// 
        /// ## Supported Aliases
        /// 
        /// * `oci.Core.getVirtualNetworks`
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
        ///     var testVcns = Oci.Core.GetVcns.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Vcn_display_name,
        ///         State = @var.Vcn_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVcnsResult> InvokeAsync(GetVcnsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVcnsResult>("oci:Core/getVcns:getVcns", args ?? new GetVcnsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vcns in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the virtual cloud networks (VCNs) in the specified compartment.
        /// 
        /// 
        /// ## Supported Aliases
        /// 
        /// * `oci.Core.getVirtualNetworks`
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
        ///     var testVcns = Oci.Core.GetVcns.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Vcn_display_name,
        ///         State = @var.Vcn_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetVcnsResult> Invoke(GetVcnsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVcnsResult>("oci:Core/getVcns:getVcns", args ?? new GetVcnsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVcnsArgs : global::Pulumi.InvokeArgs
    {
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
        private List<Inputs.GetVcnsFilterArgs>? _filters;
        public List<Inputs.GetVcnsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVcnsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetVcnsArgs()
        {
        }
        public static new GetVcnsArgs Empty => new GetVcnsArgs();
    }

    public sealed class GetVcnsInvokeArgs : global::Pulumi.InvokeArgs
    {
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
        private InputList<Inputs.GetVcnsFilterInputArgs>? _filters;
        public InputList<Inputs.GetVcnsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVcnsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetVcnsInvokeArgs()
        {
        }
        public static new GetVcnsInvokeArgs Empty => new GetVcnsInvokeArgs();
    }


    [OutputType]
    public sealed class GetVcnsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VCN.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetVcnsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The VCN's current state.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The list of virtual_networks.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVcnsVirtualNetworkResult> VirtualNetworks;

        [OutputConstructor]
        private GetVcnsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetVcnsFilterResult> filters,

            string id,

            string? state,

            ImmutableArray<Outputs.GetVcnsVirtualNetworkResult> virtualNetworks)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
            VirtualNetworks = virtualNetworks;
        }
    }
}