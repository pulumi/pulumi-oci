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
    public sealed class GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParamResult
    {
        /// <summary>
        /// A string value of the parameter.
        /// </summary>
        public readonly string StringValue;

        [OutputConstructor]
        private GetWorkspaceTaskPollRestCallConfigConfigValueConfigParamValueRequestPayloadRefValueConfigValueConfigParamValueDataParamResult(string stringValue)
        {
            StringValue = stringValue;
        }
    }
}
