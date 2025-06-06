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
    public sealed class GetMonitoredResourceTasksMonitoredResourceTasksCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// Task identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Property name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The current state of the stack monitoring resource task.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The request details for the performing the task.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitoredResourceTasksMonitoredResourceTasksCollectionItemTaskDetailResult> TaskDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
        /// </summary>
        public readonly string TenantId;
        /// <summary>
        /// The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Type of the task.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
        /// </summary>
        public readonly ImmutableArray<string> WorkRequestIds;

        [OutputConstructor]
        private GetMonitoredResourceTasksMonitoredResourceTasksCollectionItemResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string name,

            string state,

            ImmutableDictionary<string, string> systemTags,

            ImmutableArray<Outputs.GetMonitoredResourceTasksMonitoredResourceTasksCollectionItemTaskDetailResult> taskDetails,

            string tenantId,

            string timeCreated,

            string timeUpdated,

            string type,

            ImmutableArray<string> workRequestIds)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            Name = name;
            State = state;
            SystemTags = systemTags;
            TaskDetails = taskDetails;
            TenantId = tenantId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Type = type;
            WorkRequestIds = workRequestIds;
        }
    }
}
