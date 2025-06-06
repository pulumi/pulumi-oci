// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class AuthenticationPolicyNetworkPolicyArgs : global::Pulumi.ResourceArgs
    {
        [Input("networkSourceIds")]
        private InputList<string>? _networkSourceIds;

        /// <summary>
        /// (Updatable) Network Source ids
        /// </summary>
        public InputList<string> NetworkSourceIds
        {
            get => _networkSourceIds ?? (_networkSourceIds = new InputList<string>());
            set => _networkSourceIds = value;
        }

        public AuthenticationPolicyNetworkPolicyArgs()
        {
        }
        public static new AuthenticationPolicyNetworkPolicyArgs Empty => new AuthenticationPolicyNetworkPolicyArgs();
    }
}
