// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Psql.Outputs
{

    [OutputType]
    public sealed class GetConfigurationsConfigurationCollectionItemDbConfigurationOverrideItemResult
    {
        /// <summary>
        /// The configuration variable name.
        /// </summary>
        public readonly string ConfigKey;
        /// <summary>
        /// User-selected configuration variable value.
        /// </summary>
        public readonly string OverridenConfigValue;

        [OutputConstructor]
        private GetConfigurationsConfigurationCollectionItemDbConfigurationOverrideItemResult(
            string configKey,

            string overridenConfigValue)
        {
            ConfigKey = configKey;
            OverridenConfigValue = overridenConfigValue;
        }
    }
}
