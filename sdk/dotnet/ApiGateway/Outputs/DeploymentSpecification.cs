// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApiGateway.Outputs
{

    [OutputType]
    public sealed class DeploymentSpecification
    {
        /// <summary>
        /// (Updatable) Policies controlling the pushing of logs to Oracle Cloud Infrastructure Public Logging.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationLoggingPolicies? LoggingPolicies;
        /// <summary>
        /// (Updatable) Global behavior applied to all requests received by the API.
        /// </summary>
        public readonly Outputs.DeploymentSpecificationRequestPolicies? RequestPolicies;
        /// <summary>
        /// (Updatable) A list of routes that this API exposes.
        /// </summary>
        public readonly ImmutableArray<Outputs.DeploymentSpecificationRoute> Routes;

        [OutputConstructor]
        private DeploymentSpecification(
            Outputs.DeploymentSpecificationLoggingPolicies? loggingPolicies,

            Outputs.DeploymentSpecificationRequestPolicies? requestPolicies,

            ImmutableArray<Outputs.DeploymentSpecificationRoute> routes)
        {
            LoggingPolicies = loggingPolicies;
            RequestPolicies = requestPolicies;
            Routes = routes;
        }
    }
}
