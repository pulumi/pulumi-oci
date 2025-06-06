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
    public sealed class DesktopPoolSessionLifecycleActions
    {
        /// <summary>
        /// (Updatable) Action and grace period for disconnect. Session disconnect can not be used together with an `availability_policy` schedule.
        /// </summary>
        public readonly Outputs.DesktopPoolSessionLifecycleActionsDisconnect? Disconnect;
        /// <summary>
        /// (Updatable) Action and grace period for inactivity
        /// </summary>
        public readonly Outputs.DesktopPoolSessionLifecycleActionsInactivity? Inactivity;

        [OutputConstructor]
        private DesktopPoolSessionLifecycleActions(
            Outputs.DesktopPoolSessionLifecycleActionsDisconnect? disconnect,

            Outputs.DesktopPoolSessionLifecycleActionsInactivity? inactivity)
        {
            Disconnect = disconnect;
            Inactivity = inactivity;
        }
    }
}
