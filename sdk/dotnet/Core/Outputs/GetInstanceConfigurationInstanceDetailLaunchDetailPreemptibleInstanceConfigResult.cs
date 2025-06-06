// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigResult
    {
        /// <summary>
        /// The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionActionResult> PreemptionActions;

        [OutputConstructor]
        private GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigResult(ImmutableArray<Outputs.GetInstanceConfigurationInstanceDetailLaunchDetailPreemptibleInstanceConfigPreemptionActionResult> preemptionActions)
        {
            PreemptionActions = preemptionActions;
        }
    }
}
