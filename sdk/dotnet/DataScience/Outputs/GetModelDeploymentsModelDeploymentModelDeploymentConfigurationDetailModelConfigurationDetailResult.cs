// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailResult
    {
        /// <summary>
        /// The minimum network bandwidth for the model deployment.
        /// </summary>
        public readonly int BandwidthMbps;
        /// <summary>
        /// The model deployment instance configuration
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationResult> InstanceConfigurations;
        /// <summary>
        /// The maximum network bandwidth for the model deployment.
        /// </summary>
        public readonly int MaximumBandwidthMbps;
        /// <summary>
        /// The OCID of the model you want to deploy.
        /// </summary>
        public readonly string ModelId;
        /// <summary>
        /// The scaling policy to apply to each model of the deployment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailScalingPolicyResult> ScalingPolicies;

        [OutputConstructor]
        private GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailResult(
            int bandwidthMbps,

            ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationResult> instanceConfigurations,

            int maximumBandwidthMbps,

            string modelId,

            ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailScalingPolicyResult> scalingPolicies)
        {
            BandwidthMbps = bandwidthMbps;
            InstanceConfigurations = instanceConfigurations;
            MaximumBandwidthMbps = maximumBandwidthMbps;
            ModelId = modelId;
            ScalingPolicies = scalingPolicies;
        }
    }
}
