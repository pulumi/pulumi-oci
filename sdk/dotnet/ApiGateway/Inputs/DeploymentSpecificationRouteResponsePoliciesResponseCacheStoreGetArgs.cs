// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Inputs
{

    public sealed class DeploymentSpecificationRouteResponsePoliciesResponseCacheStoreGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Sets the number of seconds for a response from a backend being stored in the Response Cache before it expires.
        /// </summary>
        [Input("timeToLiveInSeconds", required: true)]
        public Input<int> TimeToLiveInSeconds { get; set; } = null!;

        /// <summary>
        /// (Updatable) Type of the Response Cache Store Policy.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public DeploymentSpecificationRouteResponsePoliciesResponseCacheStoreGetArgs()
        {
        }
        public static new DeploymentSpecificationRouteResponsePoliciesResponseCacheStoreGetArgs Empty => new DeploymentSpecificationRouteResponsePoliciesResponseCacheStoreGetArgs();
    }
}