// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Autoscaling.Outputs
{

    [OutputType]
    public sealed class GetAutoScalingConfigurationsAutoScalingConfigurationPolicyResourceActionResult
    {
        /// <summary>
        /// The action to take when autoscaling is triggered.
        /// </summary>
        public readonly string Action;
        /// <summary>
        /// The type of resource action.
        /// </summary>
        public readonly string ActionType;

        [OutputConstructor]
        private GetAutoScalingConfigurationsAutoScalingConfigurationPolicyResourceActionResult(
            string action,

            string actionType)
        {
            Action = action;
            ActionType = actionType;
        }
    }
}
