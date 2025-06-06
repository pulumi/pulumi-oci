// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts
{
    /// <summary>
    /// This resource provides the Generic Artifact resource in Oracle Cloud Infrastructure Artifacts service.
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
    ///     var testGenericArtifact = new Oci.Artifacts.GenericArtifact("test_generic_artifact", new()
    ///     {
    ///         ArtifactId = testArtifact.Id,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// GenericArtifacts can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:Artifacts/genericArtifact:GenericArtifact test_generic_artifact "generic/artifacts/{artifactId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:Artifacts/genericArtifact:GenericArtifact")]
    public partial class GenericArtifact : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
        /// </summary>
        [Output("artifactId")]
        public Output<string> ArtifactId { get; private set; } = null!;

        /// <summary>
        /// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
        /// </summary>
        [Output("artifactPath")]
        public Output<string> ArtifactPath { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// The artifact name with the format of `&lt;artifact-path&gt;:&lt;artifact-version&gt;`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
        /// </summary>
        [Output("repositoryId")]
        public Output<string> RepositoryId { get; private set; } = null!;

        /// <summary>
        /// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
        /// </summary>
        [Output("sha256")]
        public Output<string> Sha256 { get; private set; } = null!;

        /// <summary>
        /// The size of the artifact in bytes.
        /// </summary>
        [Output("sizeInBytes")]
        public Output<string> SizeInBytes { get; private set; } = null!;

        /// <summary>
        /// The current state of the artifact.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// An RFC 3339 timestamp indicating when the repository was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
        /// </summary>
        [Output("version")]
        public Output<string> Version { get; private set; } = null!;


        /// <summary>
        /// Create a GenericArtifact resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public GenericArtifact(string name, GenericArtifactArgs args, CustomResourceOptions? options = null)
            : base("oci:Artifacts/genericArtifact:GenericArtifact", name, args ?? new GenericArtifactArgs(), MakeResourceOptions(options, ""))
        {
        }

        private GenericArtifact(string name, Input<string> id, GenericArtifactState? state = null, CustomResourceOptions? options = null)
            : base("oci:Artifacts/genericArtifact:GenericArtifact", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing GenericArtifact resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static GenericArtifact Get(string name, Input<string> id, GenericArtifactState? state = null, CustomResourceOptions? options = null)
        {
            return new GenericArtifact(name, id, state, options);
        }
    }

    public sealed class GenericArtifactArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
        /// </summary>
        [Input("artifactId", required: true)]
        public Input<string> ArtifactId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        public GenericArtifactArgs()
        {
        }
        public static new GenericArtifactArgs Empty => new GenericArtifactArgs();
    }

    public sealed class GenericArtifactState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the artifact.  Example: `ocid1.genericartifact.oc1..exampleuniqueID`
        /// </summary>
        [Input("artifactId")]
        public Input<string>? ArtifactId { get; set; }

        /// <summary>
        /// A user-defined path to describe the location of an artifact. Slashes do not create a directory structure, but you can use slashes to organize the repository. An artifact path does not include an artifact version.  Example: `project01/my-web-app/artifact-abc`
        /// </summary>
        [Input("artifactPath")]
        public Input<string>? ArtifactPath { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository's compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        /// <summary>
        /// The artifact name with the format of `&lt;artifact-path&gt;:&lt;artifact-version&gt;`. The artifact name is truncated to a maximum length of 255.  Example: `project01/my-web-app/artifact-abc:1.0.0`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}` 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the repository.
        /// </summary>
        [Input("repositoryId")]
        public Input<string>? RepositoryId { get; set; }

        /// <summary>
        /// The SHA256 digest for the artifact. When you upload an artifact to the repository, a SHA256 digest is calculated and added to the artifact properties.
        /// </summary>
        [Input("sha256")]
        public Input<string>? Sha256 { get; set; }

        /// <summary>
        /// The size of the artifact in bytes.
        /// </summary>
        [Input("sizeInBytes")]
        public Input<string>? SizeInBytes { get; set; }

        /// <summary>
        /// The current state of the artifact.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// An RFC 3339 timestamp indicating when the repository was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// A user-defined string to describe the artifact version.  Example: `1.1.0` or `1.2-beta-2`
        /// </summary>
        [Input("version")]
        public Input<string>? Version { get; set; }

        public GenericArtifactState()
        {
        }
        public static new GenericArtifactState Empty => new GenericArtifactState();
    }
}
