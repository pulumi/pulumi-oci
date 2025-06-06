// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetGuardTargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationResult
    {
        /// <summary>
        /// Unique identifier of the configuration
        /// </summary>
        public readonly string ConfigKey;
        /// <summary>
        /// Configuration name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Configuration value
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetGuardTargetTargetResponderRecipeEffectiveResponderRuleDetailConfigurationResult(
            string configKey,

            string name,

            string value)
        {
            ConfigKey = configKey;
            Name = name;
            Value = value;
        }
    }
}
