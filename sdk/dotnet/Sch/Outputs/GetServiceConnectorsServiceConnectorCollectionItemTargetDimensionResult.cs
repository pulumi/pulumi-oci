// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Outputs
{

    [OutputType]
    public sealed class GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionResult
    {
        /// <summary>
        /// Instructions for extracting the value corresponding to the specified dimension key: Either extract the value as-is (static) or derive the value from a path (evaluated).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValueResult> DimensionValues;
        /// <summary>
        /// Dimension key. A valid dimension key includes only printable ASCII, excluding periods (.) and spaces. Custom dimension keys are acceptable. Avoid entering confidential information. Due to use by Service Connector Hub, the following dimension names are reserved: `connectorId`, `connectorName`, `connectorSourceType`. For information on valid dimension keys and values, see [MetricDataDetails Reference](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/datatypes/MetricDataDetails). Example: `type`
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionResult(
            ImmutableArray<Outputs.GetServiceConnectorsServiceConnectorCollectionItemTargetDimensionDimensionValueResult> dimensionValues,

            string name)
        {
            DimensionValues = dimensionValues;
            Name = name;
        }
    }
}