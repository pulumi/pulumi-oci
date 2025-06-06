// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabaseSoftwareImages
    {
        /// <summary>
        /// This data source provides the list of Autonomous Database Software Images in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of the Autonomous Database Software Images in the specified compartment.
        /// 
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
        ///     var testAutonomousDatabaseSoftwareImages = Oci.Database.GetAutonomousDatabaseSoftwareImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         ImageShapeFamily = autonomousDatabaseSoftwareImageImageShapeFamily,
        ///         DisplayName = autonomousDatabaseSoftwareImageDisplayName,
        ///         State = autonomousDatabaseSoftwareImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousDatabaseSoftwareImagesResult> InvokeAsync(GetAutonomousDatabaseSoftwareImagesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabaseSoftwareImagesResult>("oci:Database/getAutonomousDatabaseSoftwareImages:getAutonomousDatabaseSoftwareImages", args ?? new GetAutonomousDatabaseSoftwareImagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Database Software Images in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of the Autonomous Database Software Images in the specified compartment.
        /// 
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
        ///     var testAutonomousDatabaseSoftwareImages = Oci.Database.GetAutonomousDatabaseSoftwareImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         ImageShapeFamily = autonomousDatabaseSoftwareImageImageShapeFamily,
        ///         DisplayName = autonomousDatabaseSoftwareImageDisplayName,
        ///         State = autonomousDatabaseSoftwareImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseSoftwareImagesResult> Invoke(GetAutonomousDatabaseSoftwareImagesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseSoftwareImagesResult>("oci:Database/getAutonomousDatabaseSoftwareImages:getAutonomousDatabaseSoftwareImages", args ?? new GetAutonomousDatabaseSoftwareImagesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Autonomous Database Software Images in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets a list of the Autonomous Database Software Images in the specified compartment.
        /// 
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
        ///     var testAutonomousDatabaseSoftwareImages = Oci.Database.GetAutonomousDatabaseSoftwareImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         ImageShapeFamily = autonomousDatabaseSoftwareImageImageShapeFamily,
        ///         DisplayName = autonomousDatabaseSoftwareImageDisplayName,
        ///         State = autonomousDatabaseSoftwareImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseSoftwareImagesResult> Invoke(GetAutonomousDatabaseSoftwareImagesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseSoftwareImagesResult>("oci:Database/getAutonomousDatabaseSoftwareImages:getAutonomousDatabaseSoftwareImages", args ?? new GetAutonomousDatabaseSoftwareImagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDatabaseSoftwareImagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAutonomousDatabaseSoftwareImagesFilterArgs>? _filters;
        public List<Inputs.GetAutonomousDatabaseSoftwareImagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAutonomousDatabaseSoftwareImagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given image shape family exactly.
        /// </summary>
        [Input("imageShapeFamily", required: true)]
        public string ImageShapeFamily { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAutonomousDatabaseSoftwareImagesArgs()
        {
        }
        public static new GetAutonomousDatabaseSoftwareImagesArgs Empty => new GetAutonomousDatabaseSoftwareImagesArgs();
    }

    public sealed class GetAutonomousDatabaseSoftwareImagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAutonomousDatabaseSoftwareImagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetAutonomousDatabaseSoftwareImagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAutonomousDatabaseSoftwareImagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given image shape family exactly.
        /// </summary>
        [Input("imageShapeFamily", required: true)]
        public Input<string> ImageShapeFamily { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetAutonomousDatabaseSoftwareImagesInvokeArgs()
        {
        }
        public static new GetAutonomousDatabaseSoftwareImagesInvokeArgs Empty => new GetAutonomousDatabaseSoftwareImagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousDatabaseSoftwareImagesResult
    {
        /// <summary>
        /// The list of autonomous_database_software_image_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAutonomousDatabaseSoftwareImagesAutonomousDatabaseSoftwareImageCollectionResult> AutonomousDatabaseSoftwareImageCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-friendly name for the Autonomous Database Software Image. The name does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAutonomousDatabaseSoftwareImagesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// To what shape the image is meant for.
        /// </summary>
        public readonly string ImageShapeFamily;
        /// <summary>
        /// The current state of the Autonomous Database Software Image.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAutonomousDatabaseSoftwareImagesResult(
            ImmutableArray<Outputs.GetAutonomousDatabaseSoftwareImagesAutonomousDatabaseSoftwareImageCollectionResult> autonomousDatabaseSoftwareImageCollections,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetAutonomousDatabaseSoftwareImagesFilterResult> filters,

            string id,

            string imageShapeFamily,

            string? state)
        {
            AutonomousDatabaseSoftwareImageCollections = autonomousDatabaseSoftwareImageCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ImageShapeFamily = imageShapeFamily;
            State = state;
        }
    }
}
