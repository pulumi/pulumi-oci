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
    public sealed class GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetailResult
    {
        /// <summary>
        /// A model-deployment instance of type VM.Standard.E3.Flex or VM.Standard.E4.Flex allows the memory to be specified with in the range of 6 to 1024 GB. VM.Standard3.Flex memory range is between 6 and 512 GB and VM.Optimized3.Flex memory range is between 6 and 256 GB.
        /// </summary>
        public readonly double MemoryInGbs;
        /// <summary>
        /// A model-deployment instance of type VM.Standard.E3.Flex or VM.Standard.E4.Flex allows the ocpu count to be specified with in the range of 1 to 64 ocpu. VM.Standard3.Flex OCPU range is between 1 and 32 ocpu and for VM.Optimized3.Flex OCPU range is 1 to 18 ocpu.
        /// </summary>
        public readonly double Ocpus;

        [OutputConstructor]
        private GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetailResult(
            double memoryInGbs,

            double ocpus)
        {
            MemoryInGbs = memoryInGbs;
            Ocpus = ocpus;
        }
    }
}