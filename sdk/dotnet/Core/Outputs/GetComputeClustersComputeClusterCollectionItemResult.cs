// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetComputeClustersComputeClusterCollectionItemResult
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string AvailabilityDomain;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the given display name exactly.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the compute cluster.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the compute cluster was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetComputeClustersComputeClusterCollectionItemResult(
            string availabilityDomain,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string state,

            string timeCreated)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
