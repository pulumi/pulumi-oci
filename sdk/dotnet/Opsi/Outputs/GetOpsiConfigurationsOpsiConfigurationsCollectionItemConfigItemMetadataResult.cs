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
    public sealed class GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataResult
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
        /// Description of OPSI configuration.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Filter to return based on resources that match the entire display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Unit details of configuration item.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataUnitDetailResult> UnitDetails;
        /// <summary>
        /// Allowed value details of configuration item, to validate what value can be assigned to a configuration item.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataValueInputDetailResult> ValueInputDetails;

        [OutputConstructor]
        private GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataResult(
            string configItemType,

            string dataType,

            string description,

            string displayName,

            ImmutableArray<Outputs.GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataUnitDetailResult> unitDetails,

            ImmutableArray<Outputs.GetOpsiConfigurationsOpsiConfigurationsCollectionItemConfigItemMetadataValueInputDetailResult> valueInputDetails)
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