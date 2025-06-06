// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent
{
    public static class GetManagementAgentImages
    {
        /// <summary>
        /// This data source provides the list of Management Agent Images in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Get supported agent image information
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
        ///     var testManagementAgentImages = Oci.ManagementAgent.GetManagementAgentImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         InstallType = managementAgentImageInstallType,
        ///         Name = managementAgentImageName,
        ///         State = managementAgentImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagementAgentImagesResult> InvokeAsync(GetManagementAgentImagesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagementAgentImagesResult>("oci:ManagementAgent/getManagementAgentImages:getManagementAgentImages", args ?? new GetManagementAgentImagesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Management Agent Images in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Get supported agent image information
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
        ///     var testManagementAgentImages = Oci.ManagementAgent.GetManagementAgentImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         InstallType = managementAgentImageInstallType,
        ///         Name = managementAgentImageName,
        ///         State = managementAgentImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementAgentImagesResult> Invoke(GetManagementAgentImagesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementAgentImagesResult>("oci:ManagementAgent/getManagementAgentImages:getManagementAgentImages", args ?? new GetManagementAgentImagesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Management Agent Images in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Get supported agent image information
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
        ///     var testManagementAgentImages = Oci.ManagementAgent.GetManagementAgentImages.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         InstallType = managementAgentImageInstallType,
        ///         Name = managementAgentImageName,
        ///         State = managementAgentImageState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementAgentImagesResult> Invoke(GetManagementAgentImagesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementAgentImagesResult>("oci:ManagementAgent/getManagementAgentImages:getManagementAgentImages", args ?? new GetManagementAgentImagesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagementAgentImagesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment to which a request will be scoped.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetManagementAgentImagesFilterArgs>? _filters;
        public List<Inputs.GetManagementAgentImagesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagementAgentImagesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
        /// </summary>
        [Input("installType")]
        public string? InstallType { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire platform name given.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetManagementAgentImagesArgs()
        {
        }
        public static new GetManagementAgentImagesArgs Empty => new GetManagementAgentImagesArgs();
    }

    public sealed class GetManagementAgentImagesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment to which a request will be scoped.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetManagementAgentImagesFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagementAgentImagesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagementAgentImagesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return either agents or gateway types depending upon install type selected by user. By default both install type will be returned.
        /// </summary>
        [Input("installType")]
        public Input<string>? InstallType { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire platform name given.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetManagementAgentImagesInvokeArgs()
        {
        }
        public static new GetManagementAgentImagesInvokeArgs Empty => new GetManagementAgentImagesInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagementAgentImagesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetManagementAgentImagesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? InstallType;
        /// <summary>
        /// The list of management_agent_images.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementAgentImagesManagementAgentImageResult> ManagementAgentImages;
        public readonly string? Name;
        /// <summary>
        /// The current state of Management Agent Image
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetManagementAgentImagesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetManagementAgentImagesFilterResult> filters,

            string id,

            string? installType,

            ImmutableArray<Outputs.GetManagementAgentImagesManagementAgentImageResult> managementAgentImages,

            string? name,

            string? state)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            InstallType = installType;
            ManagementAgentImages = managementAgentImages;
            Name = name;
            State = state;
        }
    }
}
