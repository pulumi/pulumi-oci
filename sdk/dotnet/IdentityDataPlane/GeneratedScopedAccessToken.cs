// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.IdentityDataPlane
{
    /// <summary>
    /// This resource provides the Generate Scoped Access Token resource in Oracle Cloud Infrastructure Identity Data Plane service.
    /// 
    /// Based on the calling principal and the input payload, derive the claims and create a security token.
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
    ///     var testGenerateScopedAccessToken = new Oci.IdentityDataPlane.GeneratedScopedAccessToken("test_generate_scoped_access_token", new()
    ///     {
    ///         PublicKey = generateScopedAccessTokenPublicKey,
    ///         Scope = generateScopedAccessTokenScope,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// GenerateScopedAccessToken can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken test_generate_scoped_access_token "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken")]
    public partial class GeneratedScopedAccessToken : global::Pulumi.CustomResource
    {
        /// <summary>
        /// A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
        /// </summary>
        [Output("publicKey")]
        public Output<string> PublicKey { get; private set; } = null!;

        /// <summary>
        /// Scope definition for the scoped access token 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("scope")]
        public Output<string> Scope { get; private set; } = null!;

        /// <summary>
        /// The security token, signed by auth service
        /// </summary>
        [Output("token")]
        public Output<string> Token { get; private set; } = null!;


        /// <summary>
        /// Create a GeneratedScopedAccessToken resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public GeneratedScopedAccessToken(string name, GeneratedScopedAccessTokenArgs args, CustomResourceOptions? options = null)
            : base("oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken", name, args ?? new GeneratedScopedAccessTokenArgs(), MakeResourceOptions(options, ""))
        {
        }

        private GeneratedScopedAccessToken(string name, Input<string> id, GeneratedScopedAccessTokenState? state = null, CustomResourceOptions? options = null)
            : base("oci:IdentityDataPlane/generatedScopedAccessToken:GeneratedScopedAccessToken", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing GeneratedScopedAccessToken resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static GeneratedScopedAccessToken Get(string name, Input<string> id, GeneratedScopedAccessTokenState? state = null, CustomResourceOptions? options = null)
        {
            return new GeneratedScopedAccessToken(name, id, state, options);
        }
    }

    public sealed class GeneratedScopedAccessTokenArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
        /// </summary>
        [Input("publicKey", required: true)]
        public Input<string> PublicKey { get; set; } = null!;

        /// <summary>
        /// Scope definition for the scoped access token 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("scope", required: true)]
        public Input<string> Scope { get; set; } = null!;

        public GeneratedScopedAccessTokenArgs()
        {
        }
        public static new GeneratedScopedAccessTokenArgs Empty => new GeneratedScopedAccessTokenArgs();
    }

    public sealed class GeneratedScopedAccessTokenState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A temporary public key, owned by the service. The service also owns the corresponding private key. This public key will by put inside the security token by the auth service after successful validation of the certificate.
        /// </summary>
        [Input("publicKey")]
        public Input<string>? PublicKey { get; set; }

        /// <summary>
        /// Scope definition for the scoped access token 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("scope")]
        public Input<string>? Scope { get; set; }

        /// <summary>
        /// The security token, signed by auth service
        /// </summary>
        [Input("token")]
        public Input<string>? Token { get; set; }

        public GeneratedScopedAccessTokenState()
        {
        }
        public static new GeneratedScopedAccessTokenState Empty => new GeneratedScopedAccessTokenState();
    }
}
