// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetOpsiConfigurationConfigurationItemConfigItemMetadataValueInputDetailResult
    {
        /// <summary>
        /// Allowed value type of configuration item.
        /// </summary>
        public readonly string AllowedValueType;
        /// <summary>
        /// Maximum value limit for the configuration item.
        /// </summary>
        public readonly string MaxValue;
        /// <summary>
        /// Minimum value limit for the configuration item.
        /// </summary>
        public readonly string MinValue;
        /// <summary>
        /// Allowed values to pick for the configuration item.
        /// </summary>
        public readonly ImmutableArray<string> PossibleValues;

        [OutputConstructor]
        private GetOpsiConfigurationConfigurationItemConfigItemMetadataValueInputDetailResult(
            string allowedValueType,

            string maxValue,

            string minValue,

            ImmutableArray<string> possibleValues)
        {
            AllowedValueType = allowedValueType;
            MaxValue = maxValue;
            MinValue = minValue;
            PossibleValues = possibleValues;
        }
    }
}