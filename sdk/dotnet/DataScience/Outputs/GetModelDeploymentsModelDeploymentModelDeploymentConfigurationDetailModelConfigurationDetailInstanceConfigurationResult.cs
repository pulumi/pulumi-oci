// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience.Outputs
{

    [OutputType]
    public sealed class GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationResult
    {
        /// <summary>
        /// The shape used to launch the model deployment instances.
        /// </summary>
        public readonly string InstanceShapeName;
        /// <summary>
        /// Details for the model-deployment instance shape configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetailResult> ModelDeploymentInstanceShapeConfigDetails;

        [OutputConstructor]
        private GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationResult(
            string instanceShapeName,

            ImmutableArray<Outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetailResult> modelDeploymentInstanceShapeConfigDetails)
        {
            InstanceShapeName = instanceShapeName;
            ModelDeploymentInstanceShapeConfigDetails = modelDeploymentInstanceShapeConfigDetails;
        }
    }
}