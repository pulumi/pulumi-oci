// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfig
    {
        /// <summary>
        /// (Updatable) The action to run when the preemptible node is interrupted for eviction.
        /// </summary>
        public readonly Outputs.NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionAction PreemptionAction;

        [OutputConstructor]
        private NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfig(Outputs.NodePoolNodeConfigDetailsPlacementConfigPreemptibleNodeConfigPreemptionAction preemptionAction)
        {
            PreemptionAction = preemptionAction;
        }
    }
}
