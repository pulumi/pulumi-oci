// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Inputs
{

    public sealed class RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The details of the output variable that will be used for mapping.
        /// </summary>
        [Input("outputVariableDetails")]
        public Input<Inputs.RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailOutputVariableDetailsGetArgs>? OutputVariableDetails { get; set; }

        /// <summary>
        /// Resource Ocid.
        /// </summary>
        [Input("resourceId")]
        public Input<string>? ResourceId { get; set; }

        /// <summary>
        /// Resource Type.
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        public RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailGetArgs()
        {
        }
        public static new RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailGetArgs Empty => new RunbookRunbookVersionGroupPropertiesRunOnPreviousTaskInstanceDetailGetArgs();
    }
}
