// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class DeployStageApprovalPolicyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Approval policy type.
        /// </summary>
        [Input("approvalPolicyType", required: true)]
        public Input<string> ApprovalPolicyType { get; set; } = null!;

        /// <summary>
        /// (Updatable) A minimum number of approvals required for stage to proceed.
        /// </summary>
        [Input("numberOfApprovalsRequired", required: true)]
        public Input<int> NumberOfApprovalsRequired { get; set; } = null!;

        public DeployStageApprovalPolicyArgs()
        {
        }
        public static new DeployStageApprovalPolicyArgs Empty => new DeployStageApprovalPolicyArgs();
    }
}
