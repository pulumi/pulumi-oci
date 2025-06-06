// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer
{
    public static class GetNetworkLoadBalancer
    {
        /// <summary>
        /// This data source provides details about a specific Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves network load balancer configuration information by identifier.
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
        ///     var testNetworkLoadBalancer = Oci.NetworkLoadBalancer.GetNetworkLoadBalancer.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancerOciNetworkLoadBalancerNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNetworkLoadBalancerResult> InvokeAsync(GetNetworkLoadBalancerArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNetworkLoadBalancerResult>("oci:NetworkLoadBalancer/getNetworkLoadBalancer:getNetworkLoadBalancer", args ?? new GetNetworkLoadBalancerArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves network load balancer configuration information by identifier.
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
        ///     var testNetworkLoadBalancer = Oci.NetworkLoadBalancer.GetNetworkLoadBalancer.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancerOciNetworkLoadBalancerNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkLoadBalancerResult> Invoke(GetNetworkLoadBalancerInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkLoadBalancerResult>("oci:NetworkLoadBalancer/getNetworkLoadBalancer:getNetworkLoadBalancer", args ?? new GetNetworkLoadBalancerInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Network Load Balancer resource in Oracle Cloud Infrastructure Network Load Balancer service.
        /// 
        /// Retrieves network load balancer configuration information by identifier.
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
        ///     var testNetworkLoadBalancer = Oci.NetworkLoadBalancer.GetNetworkLoadBalancer.Invoke(new()
        ///     {
        ///         NetworkLoadBalancerId = testNetworkLoadBalancerOciNetworkLoadBalancerNetworkLoadBalancer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNetworkLoadBalancerResult> Invoke(GetNetworkLoadBalancerInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNetworkLoadBalancerResult>("oci:NetworkLoadBalancer/getNetworkLoadBalancer:getNetworkLoadBalancer", args ?? new GetNetworkLoadBalancerInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNetworkLoadBalancerArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public string NetworkLoadBalancerId { get; set; } = null!;

        public GetNetworkLoadBalancerArgs()
        {
        }
        public static new GetNetworkLoadBalancerArgs Empty => new GetNetworkLoadBalancerArgs();
    }

    public sealed class GetNetworkLoadBalancerInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network load balancer to update.
        /// </summary>
        [Input("networkLoadBalancerId", required: true)]
        public Input<string> NetworkLoadBalancerId { get; set; } = null!;

        public GetNetworkLoadBalancerInvokeArgs()
        {
        }
        public static new GetNetworkLoadBalancerInvokeArgs Empty => new GetNetworkLoadBalancerInvokeArgs();
    }


    [OutputType]
    public sealed class GetNetworkLoadBalancerResult
    {
        public readonly string AssignedIpv6;
        public readonly string AssignedPrivateIpv4;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the network load balancer.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly name, which does not have to be unique, and can be changed.  Example: `example_load_balancer`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// OCID of the reserved public IP address created with the virtual cloud network.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An array of IP addresses.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNetworkLoadBalancerIpAddressResult> IpAddresses;
        /// <summary>
        /// When enabled, the skipSourceDestinationCheck parameter is automatically enabled on the load balancer VNIC. Packets are sent to the backend set without any changes to the source and destination IP.
        /// </summary>
        public readonly bool IsPreserveSourceDestination;
        /// <summary>
        /// Whether the network load balancer has a virtual cloud network-local (private) IP address.
        /// </summary>
        public readonly bool IsPrivate;
        /// <summary>
        /// This can only be enabled when NLB is working in transparent mode with source destination header preservation enabled.  This removes the additional dependency from NLB backends(like Firewalls) to perform SNAT.
        /// </summary>
        public readonly bool IsSymmetricHashEnabled;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        public readonly string NetworkLoadBalancerId;
        /// <summary>
        /// An array of network security groups [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the network load balancer.
        /// </summary>
        public readonly ImmutableArray<string> NetworkSecurityGroupIds;
        /// <summary>
        /// IP version associated with the NLB.
        /// </summary>
        public readonly string NlbIpVersion;
        public readonly ImmutableArray<Outputs.GetNetworkLoadBalancerReservedIpResult> ReservedIps;
        /// <summary>
        /// ZPR tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{ "oracle-zpr": { "td": { "value": "42", "mode": "audit" } } }`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SecurityAttributes;
        /// <summary>
        /// The current state of the network load balancer.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The subnet in which the network load balancer is spawned [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)."
        /// </summary>
        public readonly string SubnetId;
        public readonly string SubnetIpv6cidr;
        /// <summary>
        /// Key-value pair representing system tags' keys and values scoped to a namespace. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the network load balancer was created, in the format defined by RFC3339.  Example: `2020-05-01T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the network load balancer was updated. An RFC3339 formatted date-time string.  Example: `2020-05-01T22:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetNetworkLoadBalancerResult(
            string assignedIpv6,

            string assignedPrivateIpv4,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            ImmutableArray<Outputs.GetNetworkLoadBalancerIpAddressResult> ipAddresses,

            bool isPreserveSourceDestination,

            bool isPrivate,

            bool isSymmetricHashEnabled,

            string lifecycleDetails,

            string networkLoadBalancerId,

            ImmutableArray<string> networkSecurityGroupIds,

            string nlbIpVersion,

            ImmutableArray<Outputs.GetNetworkLoadBalancerReservedIpResult> reservedIps,

            ImmutableDictionary<string, string> securityAttributes,

            string state,

            string subnetId,

            string subnetIpv6cidr,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AssignedIpv6 = assignedIpv6;
            AssignedPrivateIpv4 = assignedPrivateIpv4;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IpAddresses = ipAddresses;
            IsPreserveSourceDestination = isPreserveSourceDestination;
            IsPrivate = isPrivate;
            IsSymmetricHashEnabled = isSymmetricHashEnabled;
            LifecycleDetails = lifecycleDetails;
            NetworkLoadBalancerId = networkLoadBalancerId;
            NetworkSecurityGroupIds = networkSecurityGroupIds;
            NlbIpVersion = nlbIpVersion;
            ReservedIps = reservedIps;
            SecurityAttributes = securityAttributes;
            State = state;
            SubnetId = subnetId;
            SubnetIpv6cidr = subnetIpv6cidr;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
