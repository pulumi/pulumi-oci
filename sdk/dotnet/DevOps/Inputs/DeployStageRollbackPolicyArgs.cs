// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployStageRollbackPolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of policy used for rolling out a deployment stage.
        /// </summary>
        [Input("policyType")]
        public Input<string>? PolicyType { get; set; }

        public DeployStageRollbackPolicyArgs()
        {
        }
        public static new DeployStageRollbackPolicyArgs Empty => new DeployStageRollbackPolicyArgs();
    }
}