// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Inputs
{

    public sealed class ApplicationImagePolicyConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Define if image signature verification policy is enabled for the application.
        /// </summary>
        [Input("isPolicyEnabled", required: true)]
        public Input<bool> IsPolicyEnabled { get; set; } = null!;

        [Input("keyDetails")]
        private InputList<Inputs.ApplicationImagePolicyConfigKeyDetailGetArgs>? _keyDetails;

        /// <summary>
        /// (Updatable) A list of KMS key details.
        /// </summary>
        public InputList<Inputs.ApplicationImagePolicyConfigKeyDetailGetArgs> KeyDetails
        {
            get => _keyDetails ?? (_keyDetails = new InputList<Inputs.ApplicationImagePolicyConfigKeyDetailGetArgs>());
            set => _keyDetails = value;
        }

        public ApplicationImagePolicyConfigGetArgs()
        {
        }
        public static new ApplicationImagePolicyConfigGetArgs Empty => new ApplicationImagePolicyConfigGetArgs();
    }
}
