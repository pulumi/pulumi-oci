// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Outputs
{

    [OutputType]
    public sealed class GetBackendSetsBackendsetResult
    {
        public readonly ImmutableArray<Outputs.GetBackendSetsBackendsetBackendResult> Backends;
        /// <summary>
        /// The health check policy configuration. For more information, see [Editing Health Check Policies](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/editinghealthcheck.htm).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendSetsBackendsetHealthCheckerResult> HealthCheckers;
        public readonly string Id;
        /// <summary>
        /// The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendSetsBackendsetLbCookieSessionPersistenceConfigurationResult> LbCookieSessionPersistenceConfigurations;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer associated with the backend sets to retrieve.
        /// </summary>
        public readonly string LoadBalancerId;
        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
        /// </summary>
        public readonly string Policy;
        /// <summary>
        /// The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendSetsBackendsetSessionPersistenceConfigurationResult> SessionPersistenceConfigurations;
        /// <summary>
        /// A listener's SSL handling configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBackendSetsBackendsetSslConfigurationResult> SslConfigurations;
        public readonly string State;

        [OutputConstructor]
        private GetBackendSetsBackendsetResult(
            ImmutableArray<Outputs.GetBackendSetsBackendsetBackendResult> backends,

            ImmutableArray<Outputs.GetBackendSetsBackendsetHealthCheckerResult> healthCheckers,

            string id,

            ImmutableArray<Outputs.GetBackendSetsBackendsetLbCookieSessionPersistenceConfigurationResult> lbCookieSessionPersistenceConfigurations,

            string loadBalancerId,

            string name,

            string policy,

            ImmutableArray<Outputs.GetBackendSetsBackendsetSessionPersistenceConfigurationResult> sessionPersistenceConfigurations,

            ImmutableArray<Outputs.GetBackendSetsBackendsetSslConfigurationResult> sslConfigurations,

            string state)
        {
            Backends = backends;
            HealthCheckers = healthCheckers;
            Id = id;
            LbCookieSessionPersistenceConfigurations = lbCookieSessionPersistenceConfigurations;
            LoadBalancerId = loadBalancerId;
            Name = name;
            Policy = policy;
            SessionPersistenceConfigurations = sessionPersistenceConfigurations;
            SslConfigurations = sslConfigurations;
            State = state;
        }
    }
}