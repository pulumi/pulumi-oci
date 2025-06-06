// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetAddonOptions
    {
        /// <summary>
        /// This data source provides the list of Addon Options in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get list of supported addons for a specific kubernetes version.
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
        ///     var testAddonOptions = Oci.ContainerEngine.GetAddonOptions.Invoke(new()
        ///     {
        ///         KubernetesVersion = addonOptionKubernetesVersion,
        ///         AddonName = testAddon.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAddonOptionsResult> InvokeAsync(GetAddonOptionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAddonOptionsResult>("oci:ContainerEngine/getAddonOptions:getAddonOptions", args ?? new GetAddonOptionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Addon Options in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get list of supported addons for a specific kubernetes version.
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
        ///     var testAddonOptions = Oci.ContainerEngine.GetAddonOptions.Invoke(new()
        ///     {
        ///         KubernetesVersion = addonOptionKubernetesVersion,
        ///         AddonName = testAddon.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAddonOptionsResult> Invoke(GetAddonOptionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAddonOptionsResult>("oci:ContainerEngine/getAddonOptions:getAddonOptions", args ?? new GetAddonOptionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Addon Options in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get list of supported addons for a specific kubernetes version.
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
        ///     var testAddonOptions = Oci.ContainerEngine.GetAddonOptions.Invoke(new()
        ///     {
        ///         KubernetesVersion = addonOptionKubernetesVersion,
        ///         AddonName = testAddon.Name,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAddonOptionsResult> Invoke(GetAddonOptionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAddonOptionsResult>("oci:ContainerEngine/getAddonOptions:getAddonOptions", args ?? new GetAddonOptionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAddonOptionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the addon.
        /// </summary>
        [Input("addonName")]
        public string? AddonName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAddonOptionsFilterArgs>? _filters;
        public List<Inputs.GetAddonOptionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAddonOptionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The kubernetes version to fetch the addons.
        /// </summary>
        [Input("kubernetesVersion", required: true)]
        public string KubernetesVersion { get; set; } = null!;

        public GetAddonOptionsArgs()
        {
        }
        public static new GetAddonOptionsArgs Empty => new GetAddonOptionsArgs();
    }

    public sealed class GetAddonOptionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the addon.
        /// </summary>
        [Input("addonName")]
        public Input<string>? AddonName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAddonOptionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAddonOptionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAddonOptionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The kubernetes version to fetch the addons.
        /// </summary>
        [Input("kubernetesVersion", required: true)]
        public Input<string> KubernetesVersion { get; set; } = null!;

        public GetAddonOptionsInvokeArgs()
        {
        }
        public static new GetAddonOptionsInvokeArgs Empty => new GetAddonOptionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetAddonOptionsResult
    {
        public readonly string? AddonName;
        /// <summary>
        /// The list of addon_options.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddonOptionsAddonOptionResult> AddonOptions;
        public readonly ImmutableArray<Outputs.GetAddonOptionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string KubernetesVersion;

        [OutputConstructor]
        private GetAddonOptionsResult(
            string? addonName,

            ImmutableArray<Outputs.GetAddonOptionsAddonOptionResult> addonOptions,

            ImmutableArray<Outputs.GetAddonOptionsFilterResult> filters,

            string id,

            string kubernetesVersion)
        {
            AddonName = addonName;
            AddonOptions = addonOptions;
            Filters = filters;
            Id = id;
            KubernetesVersion = kubernetesVersion;
        }
    }
}
