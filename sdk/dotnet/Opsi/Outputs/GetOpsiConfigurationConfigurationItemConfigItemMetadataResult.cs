// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi.Outputs
{

    [OutputType]
    public sealed class GetOpsiConfigurationConfigurationItemConfigItemMetadataResult
    {
        /// <summary>
        /// Type of configuration item.
        /// </summary>
        public readonly string ConfigItemType;
        /// <summary>
        /// Data type of configuration item. Examples: STRING, BOOLEAN, NUMBER
        /// </summary>
        public readonly string DataType;
        /// <summary>
        /// Description of configuration item .
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// User-friendly display name for the configuration item unit.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Unit details of configuration item.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOpsiConfigurationConfigurationItemConfigItemMetadataUnitDetailResult> UnitDetails;
        /// <summary>
        /// Allowed value details of configuration item, to validate what value can be assigned to a configuration item.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOpsiConfigurationConfigurationItemConfigItemMetadataValueInputDetailResult> ValueInputDetails;

        [OutputConstructor]
        private GetOpsiConfigurationConfigurationItemConfigItemMetadataResult(
            string configItemType,

            string dataType,

            string description,

            string displayName,

            ImmutableArray<Outputs.GetOpsiConfigurationConfigurationItemConfigItemMetadataUnitDetailResult> unitDetails,

            ImmutableArray<Outputs.GetOpsiConfigurationConfigurationItemConfigItemMetadataValueInputDetailResult> valueInputDetails)
        {
            ConfigItemType = configItemType;
            DataType = dataType;
            Description = description;
            DisplayName = displayName;
            UnitDetails = unitDetails;
            ValueInputDetails = valueInputDetails;
        }
    }
}
