// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Outputs
{

    [OutputType]
    public sealed class ApplicationImagePolicyConfig
    {
        /// <summary>
        /// (Updatable) Define if image signature verification policy is enabled for the application.
        /// </summary>
        public readonly bool IsPolicyEnabled;
        /// <summary>
        /// (Updatable) A list of KMS key details.
        /// </summary>
        public readonly ImmutableArray<Outputs.ApplicationImagePolicyConfigKeyDetail> KeyDetails;

        [OutputConstructor]
        private ApplicationImagePolicyConfig(
            bool isPolicyEnabled,

            ImmutableArray<Outputs.ApplicationImagePolicyConfigKeyDetail> keyDetails)
        {
            IsPolicyEnabled = isPolicyEnabled;
            KeyDetails = keyDetails;
        }
    }
}