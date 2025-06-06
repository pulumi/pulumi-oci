// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Integration.Outputs
{

    [OutputType]
    public sealed class IntegrationInstanceDisasterRecoveryDetail
    {
        /// <summary>
        /// Details of integration instance created in cross region for disaster recovery.
        /// </summary>
        public readonly ImmutableArray<Outputs.IntegrationInstanceDisasterRecoveryDetailCrossRegionIntegrationInstanceDetail> CrossRegionIntegrationInstanceDetails;
        /// <summary>
        /// Region specific instance url for the integration instance in the region
        /// </summary>
        public readonly string? RegionalInstanceUrl;
        /// <summary>
        /// Role of the integration instance in the region
        /// </summary>
        public readonly string? Role;

        [OutputConstructor]
        private IntegrationInstanceDisasterRecoveryDetail(
            ImmutableArray<Outputs.IntegrationInstanceDisasterRecoveryDetailCrossRegionIntegrationInstanceDetail> crossRegionIntegrationInstanceDetails,

            string? regionalInstanceUrl,

            string? role)
        {
            CrossRegionIntegrationInstanceDetails = crossRegionIntegrationInstanceDetails;
            RegionalInstanceUrl = regionalInstanceUrl;
            Role = role;
        }
    }
}
