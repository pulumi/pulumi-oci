// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVlan
    {
        /// <summary>
        /// This data source provides details about a specific Vlan resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified VLAN's information.
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
        ///     var testVlan = Oci.Core.GetVlan.Invoke(new()
        ///     {
        ///         VlanId = oci_core_vlan.Test_vlan.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVlanResult> InvokeAsync(GetVlanArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVlanResult>("oci:Core/getVlan:getVlan", args ?? new GetVlanArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Vlan resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified VLAN's information.
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
        ///     var testVlan = Oci.Core.GetVlan.Invoke(new()
        ///     {
        ///         VlanId = oci_core_vlan.Test_vlan.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetVlanResult> Invoke(GetVlanInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVlanResult>("oci:Core/getVlan:getVlan", args ?? new GetVlanInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVlanArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN.
        /// </summary>
        [Input("vlanId", required: true)]
        public string VlanId { get; set; } = null!;

        public GetVlanArgs()
        {
        }
        public static new GetVlanArgs Empty => new GetVlanArgs();
    }

    public sealed class GetVlanInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN.
        /// </summary>
        [Input("vlanId", required: true)]
        public Input<string> VlanId { get; set; } = null!;

        public GetVlanInvokeArgs()
        {
        }
        public static new GetVlanInvokeArgs Empty => new GetVlanInvokeArgs();
    }


    [OutputType]
    public sealed class GetVlanResult
    {
        /// <summary>
        /// The VLAN's availability domain. This attribute will be null if this is a regional VLAN rather than an AD-specific VLAN.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The range of IPv4 addresses that will be used for layer 3 communication with hosts outside the VLAN.  Example: `192.168.1.0/24`
        /// </summary>
        public readonly string CidrBlock;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VLAN.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The VLAN's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A list of the OCIDs of the network security groups (NSGs) to use with this VLAN. All VNICs in the VLAN belong to these NSGs. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
        /// </summary>
        public readonly ImmutableArray<string> NsgIds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that the VLAN uses.
        /// </summary>
        public readonly string RouteTableId;
        /// <summary>
        /// The VLAN's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the VLAN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the VLAN is in.
        /// </summary>
        public readonly string VcnId;
        public readonly string VlanId;
        /// <summary>
        /// The IEEE 802.1Q VLAN tag of this VLAN.  Example: `100`
        /// </summary>
        public readonly int VlanTag;

        [OutputConstructor]
        private GetVlanResult(
            string availabilityDomain,

            string cidrBlock,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<string> nsgIds,

            string routeTableId,

            string state,

            string timeCreated,

            string vcnId,

            string vlanId,

            int vlanTag)
        {
            AvailabilityDomain = availabilityDomain;
            CidrBlock = cidrBlock;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            NsgIds = nsgIds;
            RouteTableId = routeTableId;
            State = state;
            TimeCreated = timeCreated;
            VcnId = vcnId;
            VlanId = vlanId;
            VlanTag = vlanTag;
        }
    }
}