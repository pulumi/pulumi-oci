// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Blockchain
{
    /// <summary>
    /// This resource provides the Peer resource in Oracle Cloud Infrastructure Blockchain service.
    /// 
    /// Create Blockchain Platform Peer
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
    ///     var testPeer = new Oci.Blockchain.Peer("test_peer", new()
    ///     {
    ///         Ad = peerAd,
    ///         BlockchainPlatformId = testBlockchainPlatform.Id,
    ///         OcpuAllocationParam = new Oci.Blockchain.Inputs.PeerOcpuAllocationParamArgs
    ///         {
    ///             OcpuAllocationNumber = peerOcpuAllocationParamOcpuAllocationNumber,
    ///         },
    ///         Role = peerRole,
    ///         Alias = peerAlias,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Peers can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Blockchain/peer:Peer test_peer "blockchainPlatforms/{blockchainPlatformId}/peers/{peerId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Blockchain/peer:Peer")]
    public partial class Peer : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Availability Domain to place new peer
        /// </summary>
        [Output("ad")]
        public Output<string> Ad { get; private set; } = null!;

        /// <summary>
        /// peer alias
        /// </summary>
        [Output("alias")]
        public Output<string> Alias { get; private set; } = null!;

        /// <summary>
        /// Unique service identifier.
        /// </summary>
        [Output("blockchainPlatformId")]
        public Output<string> BlockchainPlatformId { get; private set; } = null!;

        /// <summary>
        /// Host on which the Peer exists
        /// </summary>
        [Output("host")]
        public Output<string> Host { get; private set; } = null!;

        /// <summary>
        /// (Updatable) OCPU allocation parameter
        /// </summary>
        [Output("ocpuAllocationParam")]
        public Output<Outputs.PeerOcpuAllocationParam> OcpuAllocationParam { get; private set; } = null!;

        /// <summary>
        /// peer identifier
        /// </summary>
        [Output("peerKey")]
        public Output<string> PeerKey { get; private set; } = null!;

        /// <summary>
        /// Peer role
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("role")]
        public Output<string> Role { get; private set; } = null!;

        /// <summary>
        /// The current state of the peer.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a Peer resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Peer(string name, PeerArgs args, CustomResourceOptions? options = null)
            : base("oci:Blockchain/peer:Peer", name, args ?? new PeerArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Peer(string name, Input<string> id, PeerState? state = null, CustomResourceOptions? options = null)
            : base("oci:Blockchain/peer:Peer", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing Peer resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Peer Get(string name, Input<string> id, PeerState? state = null, CustomResourceOptions? options = null)
        {
            return new Peer(name, id, state, options);
        }
    }

    public sealed class PeerArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Availability Domain to place new peer
        /// </summary>
        [Input("ad", required: true)]
        public Input<string> Ad { get; set; } = null!;

        /// <summary>
        /// peer alias
        /// </summary>
        [Input("alias")]
        public Input<string>? Alias { get; set; }

        /// <summary>
        /// Unique service identifier.
        /// </summary>
        [Input("blockchainPlatformId", required: true)]
        public Input<string> BlockchainPlatformId { get; set; } = null!;

        /// <summary>
        /// (Updatable) OCPU allocation parameter
        /// </summary>
        [Input("ocpuAllocationParam", required: true)]
        public Input<Inputs.PeerOcpuAllocationParamArgs> OcpuAllocationParam { get; set; } = null!;

        /// <summary>
        /// Peer role
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("role", required: true)]
        public Input<string> Role { get; set; } = null!;

        public PeerArgs()
        {
        }
        public static new PeerArgs Empty => new PeerArgs();
    }

    public sealed class PeerState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Availability Domain to place new peer
        /// </summary>
        [Input("ad")]
        public Input<string>? Ad { get; set; }

        /// <summary>
        /// peer alias
        /// </summary>
        [Input("alias")]
        public Input<string>? Alias { get; set; }

        /// <summary>
        /// Unique service identifier.
        /// </summary>
        [Input("blockchainPlatformId")]
        public Input<string>? BlockchainPlatformId { get; set; }

        /// <summary>
        /// Host on which the Peer exists
        /// </summary>
        [Input("host")]
        public Input<string>? Host { get; set; }

        /// <summary>
        /// (Updatable) OCPU allocation parameter
        /// </summary>
        [Input("ocpuAllocationParam")]
        public Input<Inputs.PeerOcpuAllocationParamGetArgs>? OcpuAllocationParam { get; set; }

        /// <summary>
        /// peer identifier
        /// </summary>
        [Input("peerKey")]
        public Input<string>? PeerKey { get; set; }

        /// <summary>
        /// Peer role
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("role")]
        public Input<string>? Role { get; set; }

        /// <summary>
        /// The current state of the peer.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public PeerState()
        {
        }
        public static new PeerState Empty => new PeerState();
    }
}
