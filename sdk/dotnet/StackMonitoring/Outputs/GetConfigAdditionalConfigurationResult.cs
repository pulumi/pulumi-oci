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
    public sealed class GetConfigAdditionalConfigurationResult
    {
        /// <summary>
        /// Key/Value pair of Property
        /// </summary>
        public readonly ImmutableDictionary<string, string> PropertiesMap;

        [OutputConstructor]
        private GetConfigAdditionalConfigurationResult(ImmutableDictionary<string, string> propertiesMap)
        {
            PropertiesMap = propertiesMap;
        }
    }
}
