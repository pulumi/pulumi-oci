// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer
{
    /// <summary>
    /// This resource provides the Backend Set resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Adds a backend set to a load balancer.
    /// 
    /// ## Supported Aliases
    /// 
    /// * `oci_load_balancer_backendset`
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using System.Linq;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testBackendSet = new Oci.LoadBalancer.BackendSet("test_backend_set", new()
    ///     {
    ///         HealthChecker = new Oci.LoadBalancer.Inputs.BackendSetHealthCheckerArgs
    ///         {
    ///             Protocol = backendSetHealthCheckerProtocol,
    ///             IntervalMs = backendSetHealthCheckerIntervalMs,
    ///             IsForcePlainText = backendSetHealthCheckerIsForcePlainText,
    ///             Port = backendSetHealthCheckerPort,
    ///             ResponseBodyRegex = backendSetHealthCheckerResponseBodyRegex,
    ///             Retries = backendSetHealthCheckerRetries,
    ///             ReturnCode = backendSetHealthCheckerReturnCode,
    ///             TimeoutInMillis = backendSetHealthCheckerTimeoutInMillis,
    ///             UrlPath = backendSetHealthCheckerUrlPath,
    ///         },
    ///         LoadBalancerId = testLoadBalancer.Id,
    ///         Name = backendSetName,
    ///         Policy = backendSetPolicy,
    ///         BackendMaxConnections = backendSetBackendMaxConnections,
    ///         LbCookieSessionPersistenceConfiguration = new Oci.LoadBalancer.Inputs.BackendSetLbCookieSessionPersistenceConfigurationArgs
    ///         {
    ///             CookieName = backendSetLbCookieSessionPersistenceConfigurationCookieName,
    ///             DisableFallback = backendSetLbCookieSessionPersistenceConfigurationDisableFallback,
    ///             Domain = backendSetLbCookieSessionPersistenceConfigurationDomain,
    ///             IsHttpOnly = backendSetLbCookieSessionPersistenceConfigurationIsHttpOnly,
    ///             IsSecure = backendSetLbCookieSessionPersistenceConfigurationIsSecure,
    ///             MaxAgeInSeconds = backendSetLbCookieSessionPersistenceConfigurationMaxAgeInSeconds,
    ///             Path = backendSetLbCookieSessionPersistenceConfigurationPath,
    ///         },
    ///         SessionPersistenceConfiguration = new Oci.LoadBalancer.Inputs.BackendSetSessionPersistenceConfigurationArgs
    ///         {
    ///             CookieName = backendSetSessionPersistenceConfigurationCookieName,
    ///             DisableFallback = backendSetSessionPersistenceConfigurationDisableFallback,
    ///         },
    ///         SslConfiguration = new Oci.LoadBalancer.Inputs.BackendSetSslConfigurationArgs
    ///         {
    ///             CertificateIds = backendSetSslConfigurationCertificateIds,
    ///             CertificateName = testCertificate.Name,
    ///             CipherSuiteName = backendSetSslConfigurationCipherSuiteName,
    ///             Protocols = backendSetSslConfigurationProtocols,
    ///             ServerOrderPreference = backendSetSslConfigurationServerOrderPreference,
    ///             TrustedCertificateAuthorityIds = backendSetSslConfigurationTrustedCertificateAuthorityIds,
    ///             VerifyDepth = backendSetSslConfigurationVerifyDepth,
    ///             VerifyPeerCertificate = backendSetSslConfigurationVerifyPeerCertificate,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// **Note:** The `sessionPersistenceConfiguration` (application cookie stickiness) and `lbCookieSessionPersistenceConfiguration`
    ///       (LB cookie stickiness) attributes are mutually exclusive. To avoid returning an error, configure only one of these two
    ///       attributes per backend set.
    /// 
    /// ## Import
    /// 
    /// BackendSets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:LoadBalancer/backendSet:BackendSet test_backend_set "loadBalancers/{loadBalancerId}/backendSets/{backendSetName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LoadBalancer/backendSet:BackendSet")]
    public partial class BackendSet : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The maximum number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting. If this is not set or set to 0 then the number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting is unlimited.
        /// 
        /// If setting backendMaxConnections to some value other than 0 then that value must be greater or equal to 256.
        /// 
        /// Example: `300`
        /// </summary>
        [Output("backendMaxConnections")]
        public Output<int> BackendMaxConnections { get; private set; } = null!;

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Output("backends")]
        public Output<ImmutableArray<Outputs.BackendSetBackend>> Backends { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The health check policy's configuration details.
        /// </summary>
        [Output("healthChecker")]
        public Output<Outputs.BackendSetHealthChecker> HealthChecker { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct all requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// When you configure LB cookie stickiness, the load balancer inserts a cookie into the response. The parameters configured in the cookie enable session stickiness. This method is useful when you have applications and Web backend services that cannot generate their own cookies.
        /// 
        /// Path route rules take precedence to determine the target backend server. The load balancer verifies that session stickiness is enabled for the backend server and that the cookie configuration (domain, path, and cookie hash) is valid for the target. The system ignores invalid cookies.
        /// 
        /// To disable LB cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `LBCookieSessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `LBCookieSessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Output("lbCookieSessionPersistenceConfiguration")]
        public Output<Outputs.BackendSetLbCookieSessionPersistenceConfiguration> LbCookieSessionPersistenceConfiguration { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// 
        /// Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
        /// 
        /// Example: `example_backend_set`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
        /// </summary>
        [Output("policy")]
        public Output<string> Policy { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct any number of requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// With application cookie stickiness, the load balancer enables session persistence only when the response from a backend application server includes a `Set-cookie` header with the user-specified cookie name.
        /// 
        /// To disable application cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `SessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `SessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Output("sessionPersistenceConfiguration")]
        public Output<Outputs.BackendSetSessionPersistenceConfiguration> SessionPersistenceConfiguration { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Output("sslConfiguration")]
        public Output<Outputs.BackendSetSslConfiguration?> SslConfiguration { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a BackendSet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public BackendSet(string name, BackendSetArgs args, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/backendSet:BackendSet", name, args ?? new BackendSetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private BackendSet(string name, Input<string> id, BackendSetState? state = null, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/backendSet:BackendSet", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing BackendSet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static BackendSet Get(string name, Input<string> id, BackendSetState? state = null, CustomResourceOptions? options = null)
        {
            return new BackendSet(name, id, state, options);
        }
    }

    public sealed class BackendSetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The maximum number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting. If this is not set or set to 0 then the number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting is unlimited.
        /// 
        /// If setting backendMaxConnections to some value other than 0 then that value must be greater or equal to 256.
        /// 
        /// Example: `300`
        /// </summary>
        [Input("backendMaxConnections")]
        public Input<int>? BackendMaxConnections { get; set; }

        /// <summary>
        /// (Updatable) The health check policy's configuration details.
        /// </summary>
        [Input("healthChecker", required: true)]
        public Input<Inputs.BackendSetHealthCheckerArgs> HealthChecker { get; set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct all requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// When you configure LB cookie stickiness, the load balancer inserts a cookie into the response. The parameters configured in the cookie enable session stickiness. This method is useful when you have applications and Web backend services that cannot generate their own cookies.
        /// 
        /// Path route rules take precedence to determine the target backend server. The load balancer verifies that session stickiness is enabled for the backend server and that the cookie configuration (domain, path, and cookie hash) is valid for the target. The system ignores invalid cookies.
        /// 
        /// To disable LB cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `LBCookieSessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `LBCookieSessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("lbCookieSessionPersistenceConfiguration")]
        public Input<Inputs.BackendSetLbCookieSessionPersistenceConfigurationArgs>? LbCookieSessionPersistenceConfiguration { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// 
        /// Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
        /// 
        /// Example: `example_backend_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
        /// </summary>
        [Input("policy", required: true)]
        public Input<string> Policy { get; set; } = null!;

        /// <summary>
        /// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct any number of requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// With application cookie stickiness, the load balancer enables session persistence only when the response from a backend application server includes a `Set-cookie` header with the user-specified cookie name.
        /// 
        /// To disable application cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `SessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `SessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sessionPersistenceConfiguration")]
        public Input<Inputs.BackendSetSessionPersistenceConfigurationArgs>? SessionPersistenceConfiguration { get; set; }

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sslConfiguration")]
        public Input<Inputs.BackendSetSslConfigurationArgs>? SslConfiguration { get; set; }

        public BackendSetArgs()
        {
        }
        public static new BackendSetArgs Empty => new BackendSetArgs();
    }

    public sealed class BackendSetState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The maximum number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting. If this is not set or set to 0 then the number of simultaneous connections the load balancer can make to any backend in the backend set unless the backend has its own maxConnections setting is unlimited.
        /// 
        /// If setting backendMaxConnections to some value other than 0 then that value must be greater or equal to 256.
        /// 
        /// Example: `300`
        /// </summary>
        [Input("backendMaxConnections")]
        public Input<int>? BackendMaxConnections { get; set; }

        [Input("backends")]
        private InputList<Inputs.BackendSetBackendGetArgs>? _backends;

        /// <summary>
        /// (Updatable)
        /// </summary>
        public InputList<Inputs.BackendSetBackendGetArgs> Backends
        {
            get => _backends ?? (_backends = new InputList<Inputs.BackendSetBackendGetArgs>());
            set => _backends = value;
        }

        /// <summary>
        /// (Updatable) The health check policy's configuration details.
        /// </summary>
        [Input("healthChecker")]
        public Input<Inputs.BackendSetHealthCheckerGetArgs>? HealthChecker { get; set; }

        /// <summary>
        /// (Updatable) The configuration details for implementing load balancer cookie session persistence (LB cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct all requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// When you configure LB cookie stickiness, the load balancer inserts a cookie into the response. The parameters configured in the cookie enable session stickiness. This method is useful when you have applications and Web backend services that cannot generate their own cookies.
        /// 
        /// Path route rules take precedence to determine the target backend server. The load balancer verifies that session stickiness is enabled for the backend server and that the cookie configuration (domain, path, and cookie hash) is valid for the target. The system ignores invalid cookies.
        /// 
        /// To disable LB cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `LBCookieSessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `LBCookieSessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("lbCookieSessionPersistenceConfiguration")]
        public Input<Inputs.BackendSetLbCookieSessionPersistenceConfigurationGetArgs>? LbCookieSessionPersistenceConfiguration { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a backend set.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the backend set. It must be unique and it cannot be changed.
        /// 
        /// Valid backend set names include only alphanumeric characters, dashes, and underscores. Backend set names cannot contain spaces. Avoid entering confidential information.
        /// 
        /// Example: `example_backend_set`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The load balancer policy for the backend set. To get a list of available policies, use the [ListPolicies](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerPolicy/ListPolicies) operation.  Example: `LEAST_CONNECTIONS`
        /// </summary>
        [Input("policy")]
        public Input<string>? Policy { get; set; }

        /// <summary>
        /// (Updatable) The configuration details for implementing session persistence based on a user-specified cookie name (application cookie stickiness).
        /// 
        /// Session persistence enables the Load Balancing service to direct any number of requests that originate from a single logical client to a single backend web server. For more information, see [Session Persistence](https://docs.cloud.oracle.com/iaas/Content/Balance/Reference/sessionpersistence.htm).
        /// 
        /// With application cookie stickiness, the load balancer enables session persistence only when the response from a backend application server includes a `Set-cookie` header with the user-specified cookie name.
        /// 
        /// To disable application cookie stickiness on a running load balancer, use the [UpdateBackendSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/BackendSet/UpdateBackendSet) operation and specify `null` for the `SessionPersistenceConfigurationDetails` object.
        /// 
        /// Example: `SessionPersistenceConfigurationDetails: null`
        /// 
        /// **Note:** `SessionPersistenceConfigurationDetails` (application cookie stickiness) and `LBCookieSessionPersistenceConfigurationDetails` (LB cookie stickiness) are mutually exclusive. An error results if you try to enable both types of session persistence.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sessionPersistenceConfiguration")]
        public Input<Inputs.BackendSetSessionPersistenceConfigurationGetArgs>? SessionPersistenceConfiguration { get; set; }

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sslConfiguration")]
        public Input<Inputs.BackendSetSslConfigurationGetArgs>? SslConfiguration { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public BackendSetState()
        {
        }
        public static new BackendSetState Empty => new BackendSetState();
    }
}
