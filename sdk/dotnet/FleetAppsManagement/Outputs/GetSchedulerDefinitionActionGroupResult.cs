// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetSchedulerDefinitionActionGroupResult
    {
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// ID of the fleet
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// Task argument kind
        /// </summary>
        public readonly string Kind;
        /// <summary>
        /// The ID of the Runbook
        /// </summary>
        public readonly string RunbookId;
        /// <summary>
        /// The runbook version name
        /// </summary>
        public readonly string RunbookVersionName;
        /// <summary>
        /// Sequence of the Action Group. Action groups will be executed in a seuential order. All Action Groups having the same sequence will be executed parallely. If no value is provided a default value of 1 will be given.
        /// </summary>
        public readonly int Sequence;

        [OutputConstructor]
        private GetSchedulerDefinitionActionGroupResult(
            string displayName,

            string fleetId,

            string kind,

            string runbookId,

            string runbookVersionName,

            int sequence)
        {
            DisplayName = displayName;
            FleetId = fleetId;
            Kind = kind;
            RunbookId = runbookId;
            RunbookVersionName = runbookVersionName;
            Sequence = sequence;
        }
    }
}
