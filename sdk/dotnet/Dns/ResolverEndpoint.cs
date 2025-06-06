// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    /// <summary>
    /// This resource provides the Resolver Endpoint resource in Oracle Cloud Infrastructure DNS service.
    /// 
    /// Creates a new resolver endpoint in the same compartment as the resolver.
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
    ///     var testResolverEndpoint = new Oci.Dns.ResolverEndpoint("test_resolver_endpoint", new()
    ///     {
    ///         IsForwarding = resolverEndpointIsForwarding,
    ///         IsListening = resolverEndpointIsListening,
    ///         Name = resolverEndpointName,
    ///         ResolverId = testResolver.Id,
    ///         SubnetId = testSubnet.Id,
    ///         Scope = "PRIVATE",
    ///         EndpointType = resolverEndpointEndpointType,
    ///         ForwardingAddress = resolverEndpointForwardingAddress,
    ///         ListeningAddress = resolverEndpointListeningAddress,
    ///         NsgIds = resolverEndpointNsgIds,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// For legacy ResolverEndpoints created without `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{resolverEndpointName}"
    /// ```
    /// For ResolverEndpoints created using `scope`, these ResolverEndpoints can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Dns/resolverEndpoint:ResolverEndpoint test_resolver_endpoint "resolverId/{resolverId}/name/{name}/scope/{scope}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Dns/resolverEndpoint:ResolverEndpoint")]
    public partial class ResolverEndpoint : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        [Output("endpointType")]
        public Output<string> EndpointType { get; private set; } = null!;

        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        [Output("forwardingAddress")]
        public Output<string> ForwardingAddress { get; private set; } = null!;

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        [Output("isForwarding")]
        public Output<bool> IsForwarding { get; private set; } = null!;

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        [Output("isListening")]
        public Output<bool> IsListening { get; private set; } = null!;

        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        [Output("listeningAddress")]
        public Output<string> ListeningAddress { get; private set; } = null!;

        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
        /// </summary>
        [Output("nsgIds")]
        public Output<ImmutableArray<string>> NsgIds { get; private set; } = null!;

        /// <summary>
        /// The OCID of the target resolver.
        /// </summary>
        [Output("resolverId")]
        public Output<string> ResolverId { get; private set; } = null!;

        /// <summary>
        /// Value must be `PRIVATE` when creating private name resolver endpoints.
        /// </summary>
        [Output("scope")]
        public Output<string?> Scope { get; private set; } = null!;

        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        [Output("self")]
        public Output<string> Self { get; private set; } = null!;

        /// <summary>
        /// The current state of the resource.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("subnetId")]
        public Output<string> SubnetId { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a ResolverEndpoint resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ResolverEndpoint(string name, ResolverEndpointArgs args, CustomResourceOptions? options = null)
            : base("oci:Dns/resolverEndpoint:ResolverEndpoint", name, args ?? new ResolverEndpointArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ResolverEndpoint(string name, Input<string> id, ResolverEndpointState? state = null, CustomResourceOptions? options = null)
            : base("oci:Dns/resolverEndpoint:ResolverEndpoint", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ResolverEndpoint resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ResolverEndpoint Get(string name, Input<string> id, ResolverEndpointState? state = null, CustomResourceOptions? options = null)
        {
            return new ResolverEndpoint(name, id, state, options);
        }
    }

    public sealed class ResolverEndpointArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        [Input("endpointType")]
        public Input<string>? EndpointType { get; set; }

        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        [Input("forwardingAddress")]
        public Input<string>? ForwardingAddress { get; set; }

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        [Input("isForwarding", required: true)]
        public Input<bool> IsForwarding { get; set; } = null!;

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        [Input("isListening", required: true)]
        public Input<bool> IsListening { get; set; } = null!;

        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        [Input("listeningAddress")]
        public Input<string>? ListeningAddress { get; set; }

        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of the target resolver.
        /// </summary>
        [Input("resolverId", required: true)]
        public Input<string> ResolverId { get; set; } = null!;

        /// <summary>
        /// Value must be `PRIVATE` when creating private name resolver endpoints.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("subnetId", required: true)]
        public Input<string> SubnetId { get; set; } = null!;

        public ResolverEndpointArgs()
        {
        }
        public static new ResolverEndpointArgs Empty => new ResolverEndpointArgs();
    }

    public sealed class ResolverEndpointState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the owning compartment. This will match the resolver that the resolver endpoint is under and will be updated if the resolver's compartment is changed.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The type of resolver endpoint. VNIC is currently the only supported type.
        /// </summary>
        [Input("endpointType")]
        public Input<string>? EndpointType { get; set; }

        /// <summary>
        /// An IP address from which forwarded queries may be sent. For VNIC endpoints, this IP address must be part of the subnet and will be assigned by the system if unspecified when isForwarding is true.
        /// </summary>
        [Input("forwardingAddress")]
        public Input<string>? ForwardingAddress { get; set; }

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for forwarding.
        /// </summary>
        [Input("isForwarding")]
        public Input<bool>? IsForwarding { get; set; }

        /// <summary>
        /// A Boolean flag indicating whether or not the resolver endpoint is for listening.
        /// </summary>
        [Input("isListening")]
        public Input<bool>? IsListening { get; set; }

        /// <summary>
        /// An IP address to listen to queries on. For VNIC endpoints this IP address must be part of the subnet and will be assigned by the system if unspecified when isListening is true.
        /// </summary>
        [Input("listeningAddress")]
        public Input<string>? ListeningAddress { get; set; }

        /// <summary>
        /// The name of the resolver endpoint. Must be unique, case-insensitive, within the resolver.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("nsgIds")]
        private InputList<string>? _nsgIds;

        /// <summary>
        /// An array of network security group OCIDs for the resolver endpoint. These must be part of the VCN that the resolver endpoint is a part of.
        /// </summary>
        public InputList<string> NsgIds
        {
            get => _nsgIds ?? (_nsgIds = new InputList<string>());
            set => _nsgIds = value;
        }

        /// <summary>
        /// The OCID of the target resolver.
        /// </summary>
        [Input("resolverId")]
        public Input<string>? ResolverId { get; set; }

        /// <summary>
        /// Value must be `PRIVATE` when creating private name resolver endpoints.
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        [Input("self")]
        public Input<string>? Self { get; set; }

        /// <summary>
        /// The current state of the resource.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The OCID of a subnet. Must be part of the VCN that the resolver is attached to.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("subnetId")]
        public Input<string>? SubnetId { get; set; }

        /// <summary>
        /// The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ResolverEndpointState()
        {
        }
        public static new ResolverEndpointState Empty => new ResolverEndpointState();
    }
}
