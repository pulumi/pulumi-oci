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
    /// This resource provides the Ssl Cipher Suite resource in Oracle Cloud Infrastructure Load Balancer service.
    /// 
    /// Creates a custom SSL cipher suite.
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
    ///     var testSslCipherSuite = new Oci.LoadBalancer.SslCipherSuite("test_ssl_cipher_suite", new()
    ///     {
    ///         Ciphers = sslCipherSuiteCiphers,
    ///         LoadBalancerId = testLoadBalancer.Id,
    ///         Name = sslCipherSuiteName,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// SslCipherSuites can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:LoadBalancer/sslCipherSuite:SslCipherSuite test_ssl_cipher_suite "loadBalancers/{loadBalancerId}/sslCipherSuites/{name}"
    /// ```
    /// </summary>
    [OciResourceType("oci:LoadBalancer/sslCipherSuite:SslCipherSuite")]
    public partial class SslCipherSuite : global::Pulumi.CustomResource
    {
        [Output("ciphers")]
        public Output<ImmutableArray<string>> Ciphers { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Output("loadBalancerId")]
        public Output<string> LoadBalancerId { get; private set; } = null!;

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// 
        /// **Note:** The name of your user-defined cipher suite must not be the same as any of Oracle's predefined or reserved SSL cipher suite names:
        /// * oci-default-ssl-cipher-suite-v1
        /// * oci-modern-ssl-cipher-suite-v1
        /// * oci-compatible-ssl-cipher-suite-v1
        /// * oci-wider-compatible-ssl-cipher-suite-v1
        /// * oci-customized-ssl-cipher-suite
        /// * oci-default-http2-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-13-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-12-13-ssl-cipher-suite-v1
        /// * oci-tls-13-recommended-ssl-cipher-suite-v1
        /// * oci-tls-12-13-wider-ssl-cipher-suite-v1
        /// * oci-tls-11-12-13-wider-ssl-cipher-suite-v1
        /// 
        /// example: `example_cipher_suite`
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        [Output("state")]
        public Output<string> State { get; private set; } = null!;


        /// <summary>
        /// Create a SslCipherSuite resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SslCipherSuite(string name, SslCipherSuiteArgs args, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/sslCipherSuite:SslCipherSuite", name, args ?? new SslCipherSuiteArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SslCipherSuite(string name, Input<string> id, SslCipherSuiteState? state = null, CustomResourceOptions? options = null)
            : base("oci:LoadBalancer/sslCipherSuite:SslCipherSuite", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SslCipherSuite resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SslCipherSuite Get(string name, Input<string> id, SslCipherSuiteState? state = null, CustomResourceOptions? options = null)
        {
            return new SslCipherSuite(name, id, state, options);
        }
    }

    public sealed class SslCipherSuiteArgs : global::Pulumi.ResourceArgs
    {
        [Input("ciphers", required: true)]
        private InputList<string>? _ciphers;
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId", required: true)]
        public Input<string> LoadBalancerId { get; set; } = null!;

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// 
        /// **Note:** The name of your user-defined cipher suite must not be the same as any of Oracle's predefined or reserved SSL cipher suite names:
        /// * oci-default-ssl-cipher-suite-v1
        /// * oci-modern-ssl-cipher-suite-v1
        /// * oci-compatible-ssl-cipher-suite-v1
        /// * oci-wider-compatible-ssl-cipher-suite-v1
        /// * oci-customized-ssl-cipher-suite
        /// * oci-default-http2-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-13-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-12-13-ssl-cipher-suite-v1
        /// * oci-tls-13-recommended-ssl-cipher-suite-v1
        /// * oci-tls-12-13-wider-ssl-cipher-suite-v1
        /// * oci-tls-11-12-13-wider-ssl-cipher-suite-v1
        /// 
        /// example: `example_cipher_suite`
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public SslCipherSuiteArgs()
        {
        }
        public static new SslCipherSuiteArgs Empty => new SslCipherSuiteArgs();
    }

    public sealed class SslCipherSuiteState : global::Pulumi.ResourceArgs
    {
        [Input("ciphers")]
        private InputList<string>? _ciphers;
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the associated load balancer.
        /// </summary>
        [Input("loadBalancerId")]
        public Input<string>? LoadBalancerId { get; set; }

        /// <summary>
        /// A friendly name for the SSL cipher suite. It must be unique and it cannot be changed.
        /// 
        /// **Note:** The name of your user-defined cipher suite must not be the same as any of Oracle's predefined or reserved SSL cipher suite names:
        /// * oci-default-ssl-cipher-suite-v1
        /// * oci-modern-ssl-cipher-suite-v1
        /// * oci-compatible-ssl-cipher-suite-v1
        /// * oci-wider-compatible-ssl-cipher-suite-v1
        /// * oci-customized-ssl-cipher-suite
        /// * oci-default-http2-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-13-ssl-cipher-suite-v1
        /// * oci-default-http2-tls-12-13-ssl-cipher-suite-v1
        /// * oci-tls-13-recommended-ssl-cipher-suite-v1
        /// * oci-tls-12-13-wider-ssl-cipher-suite-v1
        /// * oci-tls-11-12-13-wider-ssl-cipher-suite-v1
        /// 
        /// example: `example_cipher_suite`
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        [Input("state")]
        public Input<string>? State { get; set; }

        public SslCipherSuiteState()
        {
        }
        public static new SslCipherSuiteState Empty => new SslCipherSuiteState();
    }
}
