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
    public sealed class GetDeploymentTypesDeploymentTypeCollectionResult
    {
        /// <summary>
        /// Array of DeploymentTypeSummary
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentTypesDeploymentTypeCollectionItemResult> Items;

        [OutputConstructor]
        private GetDeploymentTypesDeploymentTypeCollectionResult(ImmutableArray<Outputs.GetDeploymentTypesDeploymentTypeCollectionItemResult> items)
        {
            Items = items;
        }
    }
}