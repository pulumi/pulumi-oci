// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Desktops.Outputs
{

    [OutputType]
    public sealed class GetDesktopPoolSessionLifecycleActionResult
    {
        /// <summary>
        /// Action and grace period for disconnect
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionDisconnectResult> Disconnects;
        /// <summary>
        /// Action and grace period for inactivity
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionInactivityResult> Inactivities;

        [OutputConstructor]
        private GetDesktopPoolSessionLifecycleActionResult(
            ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionDisconnectResult> disconnects,

            ImmutableArray<Outputs.GetDesktopPoolSessionLifecycleActionInactivityResult> inactivities)
        {
            Disconnects = disconnects;
            Inactivities = inactivities;
        }
    }
}
