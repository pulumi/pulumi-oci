// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
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
    ///     var testPublicIpPoolCapacity = new Oci.Core.PublicIpPoolCapacity("test_public_ip_pool_capacity", new()
    ///     {
    ///         PublicIpPoolId = publicIpPoolId,
    ///         ByoipId = byoipId,
    ///         CidrBlock = cidrBlock,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// PublicIpPoolCapacity can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity test_public_ip_pool_capacity "publicIpPoolId/{publicIpPoolId}/byoipId/{byoipId}/cidrBlock/{cidrBlock}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity")]
    public partial class PublicIpPoolCapacity : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the Byoip Range Id object to which the cidr block belongs.
        /// </summary>
        [Output("byoipId")]
        public Output<string> ByoipId { get; private set; } = null!;

        /// <summary>
        /// The CIDR IP address range to be added to the Public Ip Pool. Example: `10.0.1.0/24`
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("cidrBlock")]
        public Output<string> CidrBlock { get; private set; } = null!;

        /// <summary>
        /// The OCID of the pool object created by the current tenancy
        /// </summary>
        [Output("publicIpPoolId")]
        public Output<string> PublicIpPoolId { get; private set; } = null!;


        /// <summary>
        /// Create a PublicIpPoolCapacity resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PublicIpPoolCapacity(string name, PublicIpPoolCapacityArgs args, CustomResourceOptions? options = null)
            : base("oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity", name, args ?? new PublicIpPoolCapacityArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PublicIpPoolCapacity(string name, Input<string> id, PublicIpPoolCapacityState? state = null, CustomResourceOptions? options = null)
            : base("oci:Core/publicIpPoolCapacity:PublicIpPoolCapacity", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PublicIpPoolCapacity resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PublicIpPoolCapacity Get(string name, Input<string> id, PublicIpPoolCapacityState? state = null, CustomResourceOptions? options = null)
        {
            return new PublicIpPoolCapacity(name, id, state, options);
        }
    }

    public sealed class PublicIpPoolCapacityArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the Byoip Range Id object to which the cidr block belongs.
        /// </summary>
        [Input("byoipId", required: true)]
        public Input<string> ByoipId { get; set; } = null!;

        /// <summary>
        /// The CIDR IP address range to be added to the Public Ip Pool. Example: `10.0.1.0/24`
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("cidrBlock", required: true)]
        public Input<string> CidrBlock { get; set; } = null!;

        /// <summary>
        /// The OCID of the pool object created by the current tenancy
        /// </summary>
        [Input("publicIpPoolId", required: true)]
        public Input<string> PublicIpPoolId { get; set; } = null!;

        public PublicIpPoolCapacityArgs()
        {
        }
        public static new PublicIpPoolCapacityArgs Empty => new PublicIpPoolCapacityArgs();
    }

    public sealed class PublicIpPoolCapacityState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the Byoip Range Id object to which the cidr block belongs.
        /// </summary>
        [Input("byoipId")]
        public Input<string>? ByoipId { get; set; }

        /// <summary>
        /// The CIDR IP address range to be added to the Public Ip Pool. Example: `10.0.1.0/24`
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("cidrBlock")]
        public Input<string>? CidrBlock { get; set; }

        /// <summary>
        /// The OCID of the pool object created by the current tenancy
        /// </summary>
        [Input("publicIpPoolId")]
        public Input<string>? PublicIpPoolId { get; set; }

        public PublicIpPoolCapacityState()
        {
        }
        public static new PublicIpPoolCapacityState Empty => new PublicIpPoolCapacityState();
    }
}
