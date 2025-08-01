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
    /// This resource provides the Listener resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Adds a listener to a load balancer.
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
    ///     var testListener = new Oci.LoadBalancer.Listener("test_listener", new()
    ///     {
    ///         DefaultBackendSetName = testBackendSet.Name,
    ///         LoadBalancerId = testLoadBalancer.Id,
    ///         Name = listenerName,
    ///         Port = listenerPort,
    ///         Protocol = listenerProtocol,
    ///         ConnectionConfiguration = new Oci.LoadBalancer.Inputs.ListenerConnectionConfigurationArgs
    ///         {
    ///             IdleTimeoutInSeconds = listenerConnectionConfigurationIdleTimeoutInSeconds,
    ///             BackendTcpProxyProtocolOptions = listenerConnectionConfigurationBackendTcpProxyProtocolOptions,
    ///             BackendTcpProxyProtocolVersion = listenerConnectionConfigurationBackendTcpProxyProtocolVersion,
    ///         },
    ///         HostnameNames = new[]
    ///         {
    ///             testHostname.Name,
    ///         },
    ///         PathRouteSetName = testPathRouteSet.Name,
    ///         RoutingPolicyName = testLoadBalancerRoutingPolicy.Name,
    ///         RuleSetNames = new[]
    ///         {
    ///             testRuleSet.Name,
    ///         },
    ///         SslConfiguration = new Oci.LoadBalancer.Inputs.ListenerSslConfigurationArgs
    ///         {
    ///             CertificateName = testCertificate.Name,
    ///             HasSessionResumption = listenerSslConfigurationHasSessionResumption,
    ///             CertificateIds = listenerSslConfigurationCertificateIds,
    ///             CipherSuiteName = listenerSslConfigurationCipherSuiteName,
    ///             Protocols = listenerSslConfigurationProtocols,
    ///             ServerOrderPreference = listenerSslConfigurationServerOrderPreference,
    ///             TrustedCertificateAuthorityIds = listenerSslConfigurationTrustedCertificateAuthorityIds,
    ///             VerifyDepth = listenerSslConfigurationVerifyDepth,
    ///             VerifyPeerCertificate = listenerSslConfigurationVerifyPeerCertificate,
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Listeners can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:LoadBalancer/listener:Listener test_listener "loadBalancers/{loadBalancerId}/listeners/{listenerName}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LoadBalancer/listener:Listener")]
    public partial class Listener : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Configuration details for the connection between the client and backend servers.
        /// </summary>
        [Output("connectionConfiguration")]
        public Output<Outputs.ListenerConnectionConfiguration> ConnectionConfiguration { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Output("defaultBackendSetName")]
        public Output<string> DefaultBackendSetName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) An array of hostname resource names.
        /// </summary>
        [Output("hostnameNames")]
        public Output<ImmutableArray<string>> HostnameNames { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a listener.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_listener`
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Deprecated. Please use `routingPolicies` instead.
        /// 
        /// The name of the set of path-based routing rules, [PathRouteSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/PathRouteSet/), applied to this listener's traffic.
        /// 
        /// Example: `example_path_route_set`
        /// </summary>
        [Output("pathRouteSetName")]
        public Output<string?> PathRouteSetName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Output("port")]
        public Output<int> Port { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. To get a list of valid protocols, use the [ListProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerProtocol/ListProtocols) operation.  Example: `HTTP`
        /// </summary>
        [Output("protocol")]
        public Output<string> Protocol { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The name of the routing policy applied to this listener's traffic.  Example: `example_routing_policy`
        /// </summary>
        [Output("routingPolicyName")]
        public Output<string?> RoutingPolicyName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The names of the [rule sets](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/RuleSet/) to apply to the listener.  Example: ["example_rule_set"]
        /// </summary>
        [Output("ruleSetNames")]
        public Output<ImmutableArray<string>> RuleSetNames { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Output("sslConfiguration")]
        public Output<Outputs.ListenerSslConfiguration?> SslConfiguration { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a Listener resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Listener(string name, ListenerArgs args, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/listener:Listener", name, args ?? new ListenerArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Listener(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/listener:Listener", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Listener resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Listener Get(string name, Input<string> id, ListenerState? state = null, CustomResourceOptions? options = null)
        {
            return new Listener(name, id, state, options);
        }
    }

    public sealed class ListenerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Configuration details for the connection between the client and backend servers.
        /// </summary>
        [Input("connectionConfiguration")]
        public Input<Inputs.ListenerConnectionConfigurationArgs>? ConnectionConfiguration { get; set; }

        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName", required: true)]
        public Input<string> DefaultBackendSetName { get; set; } = null!;

        [Input("hostnameNames")]
        private InputList<string>? _hostnameNames;

        /// <summary>
        /// (Updatable) An array of hostname resource names.
        /// </summary>
        public InputList<string> HostnameNames
        {
            get => _hostnameNames ?? (_hostnameNames = new InputList<string>());
            set => _hostnameNames = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a listener.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) Deprecated. Please use `routingPolicies` instead.
        /// 
        /// The name of the set of path-based routing rules, [PathRouteSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/PathRouteSet/), applied to this listener's traffic.
        /// 
        /// Example: `example_path_route_set`
        /// </summary>
        [Input("pathRouteSetName")]
        public Input<string>? PathRouteSetName { get; set; }

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port", required: true)]
        public Input<int> Port { get; set; } = null!;

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. To get a list of valid protocols, use the [ListProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerProtocol/ListProtocols) operation.  Example: `HTTP`
        /// </summary>
        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        /// <summary>
        /// (Updatable) The name of the routing policy applied to this listener's traffic.  Example: `example_routing_policy`
        /// </summary>
        [Input("routingPolicyName")]
        public Input<string>? RoutingPolicyName { get; set; }

        [Input("ruleSetNames")]
        private InputList<string>? _ruleSetNames;

        /// <summary>
        /// (Updatable) The names of the [rule sets](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/RuleSet/) to apply to the listener.  Example: ["example_rule_set"]
        /// </summary>
        public InputList<string> RuleSetNames
        {
            get => _ruleSetNames ?? (_ruleSetNames = new InputList<string>());
            set => _ruleSetNames = value;
        }

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sslConfiguration")]
        public Input<Inputs.ListenerSslConfigurationArgs>? SslConfiguration { get; set; }

        public ListenerArgs()
        {
        }
        public static new ListenerArgs Empty => new ListenerArgs();
    }

    public sealed class ListenerState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Configuration details for the connection between the client and backend servers.
        /// </summary>
        [Input("connectionConfiguration")]
        public Input<Inputs.ListenerConnectionConfigurationGetArgs>? ConnectionConfiguration { get; set; }

        /// <summary>
        /// (Updatable) The name of the associated backend set.  Example: `example_backend_set`
        /// </summary>
        [Input("defaultBackendSetName")]
        public Input<string>? DefaultBackendSetName { get; set; }

        [Input("hostnameNames")]
        private InputList<string>? _hostnameNames;

        /// <summary>
        /// (Updatable) An array of hostname resource names.
        /// </summary>
        public InputList<string> HostnameNames
        {
            get => _hostnameNames ?? (_hostnameNames = new InputList<string>());
            set => _hostnameNames = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer on which to add a listener.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the listener. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `example_listener`
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) Deprecated. Please use `routingPolicies` instead.
        /// 
        /// The name of the set of path-based routing rules, [PathRouteSet](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/PathRouteSet/), applied to this listener's traffic.
        /// 
        /// Example: `example_path_route_set`
        /// </summary>
        [Input("pathRouteSetName")]
        public Input<string>? PathRouteSetName { get; set; }

        /// <summary>
        /// (Updatable) The communication port for the listener.  Example: `80`
        /// </summary>
        [Input("port")]
        public Input<int>? Port { get; set; }

        /// <summary>
        /// (Updatable) The protocol on which the listener accepts connection requests. To get a list of valid protocols, use the [ListProtocols](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/LoadBalancerProtocol/ListProtocols) operation.  Example: `HTTP`
        /// </summary>
        [Input("protocol")]
        public Input<string>? Protocol { get; set; }

        /// <summary>
        /// (Updatable) The name of the routing policy applied to this listener's traffic.  Example: `example_routing_policy`
        /// </summary>
        [Input("routingPolicyName")]
        public Input<string>? RoutingPolicyName { get; set; }

        [Input("ruleSetNames")]
        private InputList<string>? _ruleSetNames;

        /// <summary>
        /// (Updatable) The names of the [rule sets](https://docs.cloud.oracle.com/iaas/api/#/en/loadbalancer/20170115/RuleSet/) to apply to the listener.  Example: ["example_rule_set"]
        /// </summary>
        public InputList<string> RuleSetNames
        {
            get => _ruleSetNames ?? (_ruleSetNames = new InputList<string>());
            set => _ruleSetNames = value;
        }

        /// <summary>
        /// (Updatable) The load balancer's SSL handling configuration details.
        /// 
        /// **Warning:** Oracle recommends that you avoid using any confidential information when you supply string values using the API.
        /// </summary>
        [Input("sslConfiguration")]
        public Input<Inputs.ListenerSslConfigurationGetArgs>? SslConfiguration { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public ListenerState()
        {
        }
        public static new ListenerState Empty => new ListenerState();
    }
}
