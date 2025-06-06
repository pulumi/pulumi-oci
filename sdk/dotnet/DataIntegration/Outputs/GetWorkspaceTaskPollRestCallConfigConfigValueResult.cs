// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataIntegration.Outputs
{

    [OutputType]
    public sealed class GetWorkspaceTaskPollRestCallConfigConfigValueResult
    {
        /// <summary>
        /// The configuration parameter values.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueResult> ConfigParamValues;
        /// <summary>
        /// A reference to the object's parent.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetWorkspaceTaskPollRestCallConfigConfigValueParentRefResult> ParentReves;

        [OutputConstructor]
        private GetWorkspaceTaskPollRestCallConfigConfigValueResult(
            ImmutableArray<Outputs.GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueResult> configParamValues,

            ImmutableArray<Outputs.GetWorkspaceTaskPollRestCallConfigConfigValueParentRefResult> parentReves)
        {
            ConfigParamValues = configParamValues;
            ParentReves = parentReves;
        }
    }
}
