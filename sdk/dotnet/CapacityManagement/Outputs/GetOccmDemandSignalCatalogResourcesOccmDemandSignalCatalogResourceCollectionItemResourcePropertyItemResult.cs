// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement.Outputs
{

    [OutputType]
    public sealed class GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemResult
    {
        /// <summary>
        /// This will indicate if demand signal resource's property is editable.
        /// </summary>
        public readonly bool IsEditable;
        /// <summary>
        /// The maximum value of demand signal resource's property. This is an optional parameter.
        /// </summary>
        public readonly string PropertyMaxValue;
        /// <summary>
        /// The minimum value of demand signal resource's property. This is an optional parameter.
        /// </summary>
        public readonly string PropertyMinValue;
        /// <summary>
        /// The name of demand signal resource's property.
        /// </summary>
        public readonly string PropertyName;
        /// <summary>
        /// Predefined options for demand signal resource's property. This is an optional parameter.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemPropertyOptionResult> PropertyOptions;
        /// <summary>
        /// Unit for demand signal resource's property.
        /// </summary>
        public readonly string PropertyUnit;
        /// <summary>
        /// Default value of demand signal resource's property.
        /// </summary>
        public readonly string PropertyValue;

        [OutputConstructor]
        private GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemResult(
            bool isEditable,

            string propertyMaxValue,

            string propertyMinValue,

            string propertyName,

            ImmutableArray<Outputs.GetOccmDemandSignalCatalogResourcesOccmDemandSignalCatalogResourceCollectionItemResourcePropertyItemPropertyOptionResult> propertyOptions,

            string propertyUnit,

            string propertyValue)
        {
            IsEditable = isEditable;
            PropertyMaxValue = propertyMaxValue;
            PropertyMinValue = propertyMinValue;
            PropertyName = propertyName;
            PropertyOptions = propertyOptions;
            PropertyUnit = propertyUnit;
            PropertyValue = propertyValue;
        }
    }
}
