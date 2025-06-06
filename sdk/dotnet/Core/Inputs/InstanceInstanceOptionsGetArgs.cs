// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceInstanceOptionsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Whether to disable the legacy (/v1) instance metadata service endpoints. Customers who have migrated to /v2 should set this to true for added security. Default is false.
        /// </summary>
        [Input("areLegacyImdsEndpointsDisabled")]
        public Input<bool>? AreLegacyImdsEndpointsDisabled { get; set; }

        public InstanceInstanceOptionsGetArgs()
        {
        }
        public static new InstanceInstanceOptionsGetArgs Empty => new InstanceInstanceOptionsGetArgs();
    }
}
