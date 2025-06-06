// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetPluginErrorsPluginErrorCollectionItemResult
    {
        /// <summary>
        /// The agent type.
        /// </summary>
        public readonly string AgentType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// List of plugin error details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPluginErrorsPluginErrorCollectionItemErrorResult> Errors;
        /// <summary>
        /// The HostName or Compute Instance name of the Managed Instance running the plugin.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// The Fleet-unique identifier of the managed instance.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The timestamp of the first time an error was detected.
        /// </summary>
        public readonly string TimeFirstSeen;
        /// <summary>
        /// The timestamp of the last time an error was detected.
        /// </summary>
        public readonly string TimeLastSeen;

        [OutputConstructor]
        private GetPluginErrorsPluginErrorCollectionItemResult(
            string agentType,

            string compartmentId,

            ImmutableArray<Outputs.GetPluginErrorsPluginErrorCollectionItemErrorResult> errors,

            string hostName,

            string managedInstanceId,

            string timeFirstSeen,

            string timeLastSeen)
        {
            AgentType = agentType;
            CompartmentId = compartmentId;
            Errors = errors;
            HostName = hostName;
            ManagedInstanceId = managedInstanceId;
            TimeFirstSeen = timeFirstSeen;
            TimeLastSeen = timeLastSeen;
        }
    }
}
