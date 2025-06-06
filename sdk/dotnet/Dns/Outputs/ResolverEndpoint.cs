// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Outputs
{

    [OutputType]
    public sealed class ResolverEndpoint
    {
        /// <summary>
        /// (Updatable) The OCID of the owning compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        public readonly string? EndpointType;
        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        public readonly string? ForwardingAddress;
        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        public readonly bool? IsForwarding;
        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        public readonly bool? IsListening;
        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        public readonly string? ListeningAddress;
        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        public readonly string? Self;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// </summary>
        public readonly string? SubnetId;
        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string? TimeCreated;
        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        public readonly string? TimeUpdated;

        [OutputConstructor]
        private ResolverEndpoint(
            string? compartmentId,

            string? endpointType,

            string? forwardingAddress,

            bool? isForwarding,

            bool? isListening,

            string? listeningAddress,

            string? name,

            string? self,

            string? state,

            string? subnetId,

            string? timeCreated,

            string? timeUpdated)
        {
            CompartmentId = compartmentId;
            EndpointType = endpointType;
            ForwardingAddress = forwardingAddress;
            IsForwarding = isForwarding;
            IsListening = isListening;
            ListeningAddress = listeningAddress;
            Name = name;
            Self = self;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
