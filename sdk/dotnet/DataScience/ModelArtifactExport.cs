// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    [OciResourceType("oci:DataScience/modelArtifactExport:ModelArtifactExport")]
    public partial class ModelArtifactExport : global::Pulumi.CustomResource
    {
        [Output("artifactSourceType")]
        public Output<string> ArtifactSourceType { get; private set; } = null!;

        [Output("modelId")]
        public Output<string> ModelId { get; private set; } = null!;

        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;

        [Output("sourceBucket")]
        public Output<string> SourceBucket { get; private set; } = null!;

        [Output("sourceObjectName")]
        public Output<string> SourceObjectName { get; private set; } = null!;

        [Output("sourceRegion")]
        public Output<string> SourceRegion { get; private set; } = null!;


        /// <summary>
        /// Create a ModelArtifactExport resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ModelArtifactExport(string name, ModelArtifactExportArgs args, CustomResourceOptions? options = null)
            : base("oci:DataScience/modelArtifactExport:ModelArtifactExport", name, args ?? new ModelArtifactExportArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ModelArtifactExport(string name, Input<string> id, ModelArtifactExportState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataScience/modelArtifactExport:ModelArtifactExport", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ModelArtifactExport resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ModelArtifactExport Get(string name, Input<string> id, ModelArtifactExportState? state = null, CustomResourceOptions? options = null)
        {
            return new ModelArtifactExport(name, id, state, options);
        }
    }

    public sealed class ModelArtifactExportArgs : global::Pulumi.ResourceArgs
    {
        [Input("artifactSourceType", required: true)]
        public Input<string> ArtifactSourceType { get; set; } = null!;

        [Input("modelId", required: true)]
        public Input<string> ModelId { get; set; } = null!;

        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        [Input("sourceBucket", required: true)]
        public Input<string> SourceBucket { get; set; } = null!;

        [Input("sourceObjectName", required: true)]
        public Input<string> SourceObjectName { get; set; } = null!;

        [Input("sourceRegion", required: true)]
        public Input<string> SourceRegion { get; set; } = null!;

        public ModelArtifactExportArgs()
        {
        }
        public static new ModelArtifactExportArgs Empty => new ModelArtifactExportArgs();
    }

    public sealed class ModelArtifactExportState : global::Pulumi.ResourceArgs
    {
        [Input("artifactSourceType")]
        public Input<string>? ArtifactSourceType { get; set; }

        [Input("modelId")]
        public Input<string>? ModelId { get; set; }

        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        [Input("sourceBucket")]
        public Input<string>? SourceBucket { get; set; }

        [Input("sourceObjectName")]
        public Input<string>? SourceObjectName { get; set; }

        [Input("sourceRegion")]
        public Input<string>? SourceRegion { get; set; }

        public ModelArtifactExportState()
        {
        }
        public static new ModelArtifactExportState Empty => new ModelArtifactExportState();
    }
}