// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployStageRollbackPolicyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Specifies type of the deployment stage rollback policy.
        /// </summary>
        [Input("policyType")]
        public Input<string>? PolicyType { get; set; }

        public DeployStageRollbackPolicyGetArgs()
        {
        }
        public static new DeployStageRollbackPolicyGetArgs Empty => new DeployStageRollbackPolicyGetArgs();
    }
}
