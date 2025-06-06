// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetPrivateIp
    {
        /// <summary>
        /// This data source provides details about a specific Private Ip resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified private IP. You must specify the object's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// Alternatively, you can get the object by using
        /// [ListPrivateIps](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PrivateIp/ListPrivateIps)
        /// with the private IP address (for example, 10.0.3.3) and subnet [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
        ///     var testPrivateIp = Oci.Core.GetPrivateIp.Invoke(new()
        ///     {
        ///         PrivateIpId = testPrivateIpOciCorePrivateIp.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPrivateIpResult> InvokeAsync(GetPrivateIpArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPrivateIpResult>("oci:Core/getPrivateIp:getPrivateIp", args ?? new GetPrivateIpArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Ip resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified private IP. You must specify the object's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// Alternatively, you can get the object by using
        /// [ListPrivateIps](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PrivateIp/ListPrivateIps)
        /// with the private IP address (for example, 10.0.3.3) and subnet [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
        ///     var testPrivateIp = Oci.Core.GetPrivateIp.Invoke(new()
        ///     {
        ///         PrivateIpId = testPrivateIpOciCorePrivateIp.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateIpResult> Invoke(GetPrivateIpInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateIpResult>("oci:Core/getPrivateIp:getPrivateIp", args ?? new GetPrivateIpInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Private Ip resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified private IP. You must specify the object's [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// Alternatively, you can get the object by using
        /// [ListPrivateIps](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/PrivateIp/ListPrivateIps)
        /// with the private IP address (for example, 10.0.3.3) and subnet [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
        ///     var testPrivateIp = Oci.Core.GetPrivateIp.Invoke(new()
        ///     {
        ///         PrivateIpId = testPrivateIpOciCorePrivateIp.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPrivateIpResult> Invoke(GetPrivateIpInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPrivateIpResult>("oci:Core/getPrivateIp:getPrivateIp", args ?? new GetPrivateIpInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPrivateIpArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private IP or IPv6.
        /// </summary>
        [Input("privateIpId", required: true)]
        public string PrivateIpId { get; set; } = null!;

        public GetPrivateIpArgs()
        {
        }
        public static new GetPrivateIpArgs Empty => new GetPrivateIpArgs();
    }

    public sealed class GetPrivateIpInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private IP or IPv6.
        /// </summary>
        [Input("privateIpId", required: true)]
        public Input<string> PrivateIpId { get; set; } = null!;

        public GetPrivateIpInvokeArgs()
        {
        }
        public static new GetPrivateIpInvokeArgs Empty => new GetPrivateIpInvokeArgs();
    }


    [OutputType]
    public sealed class GetPrivateIpResult
    {
        /// <summary>
        /// The private IP's availability domain. This attribute will be null if this is a *secondary* private IP assigned to a VNIC that is in a *regional* subnet.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the private IP.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The hostname for the private IP. Used for DNS. The value is the hostname portion of the private IP's fully qualified domain name (FQDN) (for example, `bminstance1` in FQDN `bminstance1.subnet123.vcn1.oraclevcn.com`). Must be unique across all VNICs in the subnet and comply with [RFC 952](https://tools.ietf.org/html/rfc952) and [RFC 1123](https://tools.ietf.org/html/rfc1123).
        /// </summary>
        public readonly string HostnameLabel;
        /// <summary>
        /// The private IP's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The private IP address of the `privateIp` object. The address is within the CIDR of the VNIC's subnet.
        /// </summary>
        public readonly string IpAddress;
        /// <summary>
        /// State of the IP address. If an IP address is assigned to a VNIC it is ASSIGNED, otherwise it is AVAILABLE.
        /// </summary>
        public readonly string IpState;
        /// <summary>
        /// Whether this private IP is the primary one on the VNIC. Primary private IPs are unassigned and deleted automatically when the VNIC is terminated.  Example: `true`
        /// </summary>
        public readonly bool IsPrimary;
        public readonly bool IsReserved;
        /// <summary>
        /// Lifetime of the IP address. There are two types of IPv6 IPs:
        /// * Ephemeral
        /// * Reserved
        /// </summary>
        public readonly string Lifetime;
        public readonly string PrivateIpId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
        /// </summary>
        public readonly string RouteTableId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet the VNIC is in.
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The date and time the private IP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Applicable only if the `PrivateIp` object is being used with a VLAN as part of the Oracle Cloud VMware Solution. The `vlanId` is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN. See [Vlan](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Vlan).
        /// </summary>
        public readonly string VlanId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC the private IP is assigned to. The VNIC and private IP must be in the same subnet. However, if the `PrivateIp` object is being used with a VLAN as part of the Oracle Cloud VMware Solution, the `vnicId` is null.
        /// </summary>
        public readonly string VnicId;

        [OutputConstructor]
        private GetPrivateIpResult(
            string availabilityDomain,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string hostnameLabel,

            string id,

            string ipAddress,

            string ipState,

            bool isPrimary,

            bool isReserved,

            string lifetime,

            string privateIpId,

            string routeTableId,

            string subnetId,

            string timeCreated,

            string vlanId,

            string vnicId)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            HostnameLabel = hostnameLabel;
            Id = id;
            IpAddress = ipAddress;
            IpState = ipState;
            IsPrimary = isPrimary;
            IsReserved = isReserved;
            Lifetime = lifetime;
            PrivateIpId = privateIpId;
            RouteTableId = routeTableId;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            VlanId = vlanId;
            VnicId = vnicId;
        }
    }
}
