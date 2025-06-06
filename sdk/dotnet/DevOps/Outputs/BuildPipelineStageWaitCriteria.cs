// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class BuildPipelineStageWaitCriteria
    {
        /// <summary>
        /// (Updatable) The absolute wait duration. Minimum wait duration must be 5 seconds. Maximum wait duration can be up to 2 days.
        /// </summary>
        public readonly string WaitDuration;
        /// <summary>
        /// (Updatable) Wait criteria type.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string WaitType;

        [OutputConstructor]
        private BuildPipelineStageWaitCriteria(
            string waitDuration,

            string waitType)
        {
            WaitDuration = waitDuration;
            WaitType = waitType;
        }
    }
}
