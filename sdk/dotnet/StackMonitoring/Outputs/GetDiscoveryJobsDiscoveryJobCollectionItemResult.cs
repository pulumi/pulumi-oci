// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class GetDiscoveryJobsDiscoveryJobCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which data is listed.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Add option submits new discovery Job. Add with retry option to re-submit failed discovery job. Refresh option refreshes the existing discovered resources.
        /// </summary>
        public readonly string DiscoveryType;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of Discovery job
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The Name of resource type
        /// </summary>
        public readonly string ResourceName;
        /// <summary>
        /// Resource Type.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// The current state of the DiscoveryJob Resource.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Specifies the status of the discovery job
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The short summary of the status of the discovery job
        /// </summary>
        public readonly string StatusMessage;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The OCID of Tenant
        /// </summary>
        public readonly string TenantId;
        /// <summary>
        /// The time the discovery Job was updated.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The OCID of user in which the job is submitted
        /// </summary>
        public readonly string UserId;

        [OutputConstructor]
        private GetDiscoveryJobsDiscoveryJobCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string discoveryType,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string resourceName,

            string resourceType,

            string state,

            string status,

            string statusMessage,

            ImmutableDictionary<string, string> systemTags,

            string tenantId,

            string timeUpdated,

            string userId)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DiscoveryType = discoveryType;
            FreeformTags = freeformTags;
            Id = id;
            ResourceName = resourceName;
            ResourceType = resourceType;
            State = state;
            Status = status;
            StatusMessage = statusMessage;
            SystemTags = systemTags;
            TenantId = tenantId;
            TimeUpdated = timeUpdated;
            UserId = userId;
        }
    }
}
