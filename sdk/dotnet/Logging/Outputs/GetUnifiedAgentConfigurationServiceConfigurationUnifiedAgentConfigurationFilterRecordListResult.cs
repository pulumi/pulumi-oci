// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Outputs
{

    [OutputType]
    public sealed class GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterRecordListResult
    {
        /// <summary>
        /// A new key
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A new value
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetUnifiedAgentConfigurationServiceConfigurationUnifiedAgentConfigurationFilterRecordListResult(
            string key,

            string value)
        {
            Key = key;
            Value = value;
        }
    }
}
