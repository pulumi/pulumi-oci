// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Kms.Outputs
{

    [OutputType]
    public sealed class GetEkmsPrivateEndpointsEkmsPrivateEndpointResult
    {
        /// <summary>
        /// CABundle to validate TLS certificate of the external key manager system in PEM format
        /// </summary>
        public readonly string CaBundle;
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Mutable name of the EKMS private endpoint
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Private IP of the external key manager system to connect to from the EKMS private endpoint
        /// </summary>
        public readonly string ExternalKeyManagerIp;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Unique identifier that is immutable
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in 'Failed' state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The port of the external key manager system
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The IP address in the customer's VCN for the EKMS private endpoint. This is taken from subnet
        /// </summary>
        public readonly string PrivateEndpointIp;
        /// <summary>
        /// The current state of the EKMS private endpoint resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Subnet Identifier
        /// </summary>
        public readonly string SubnetId;
        /// <summary>
        /// The time the EKMS private endpoint was created. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the EKMS private endpoint was updated. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetEkmsPrivateEndpointsEkmsPrivateEndpointResult(
            string caBundle,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalKeyManagerIp,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string lifecycleDetails,

            int port,

            string privateEndpointIp,

            string state,

            string subnetId,

            string timeCreated,

            string timeUpdated)
        {
            CaBundle = caBundle;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalKeyManagerIp = externalKeyManagerIp;
            FreeformTags = freeformTags;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            Port = port;
            PrivateEndpointIp = privateEndpointIp;
            State = state;
            SubnetId = subnetId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
