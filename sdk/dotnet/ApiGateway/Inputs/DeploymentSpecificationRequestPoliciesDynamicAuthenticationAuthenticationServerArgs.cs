// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Information on how to authenticate incoming requests.
        /// </summary>
        [Input("authenticationServerDetail", required: true)]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailArgs> AuthenticationServerDetail { get; set; } = null!;

        /// <summary>
        /// (Updatable) Information around the values for selector of an authentication/ routing branch.
        /// </summary>
        [Input("key", required: true)]
        public Input<Inputs.DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerKeyArgs> Key { get; set; } = null!;

        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerArgs()
        {
        }
        public static new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerArgs Empty => new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerArgs();
    }
}