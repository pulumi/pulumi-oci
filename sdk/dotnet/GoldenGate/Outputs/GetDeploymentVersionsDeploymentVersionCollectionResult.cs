// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetDeploymentVersionsDeploymentVersionCollectionResult
    {
        /// <summary>
        /// Array of DeploymentVersionSummary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentVersionsDeploymentVersionCollectionItemResult> Items;

        [OutputConstructor]
        private GetDeploymentVersionsDeploymentVersionCollectionResult(ImmutableArray<Outputs.GetDeploymentVersionsDeploymentVersionCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
