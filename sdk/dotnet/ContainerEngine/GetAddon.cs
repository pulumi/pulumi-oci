// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine
{
    public static class GetAddon
    {
        /// <summary>
        /// This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the specified addon for a cluster.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAddon = Oci.ContainerEngine.GetAddon.Invoke(new()
        ///     {
        ///         AddonName = oci_containerengine_addon.Test_addon.Name,
        ///         ClusterId = oci_containerengine_cluster.Test_cluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAddonResult> InvokeAsync(GetAddonArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAddonResult>("oci:ContainerEngine/getAddon:getAddon", args ?? new GetAddonArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.
        /// 
        /// Get the specified addon for a cluster.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testAddon = Oci.ContainerEngine.GetAddon.Invoke(new()
        ///     {
        ///         AddonName = oci_containerengine_addon.Test_addon.Name,
        ///         ClusterId = oci_containerengine_cluster.Test_cluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAddonResult> Invoke(GetAddonInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAddonResult>("oci:ContainerEngine/getAddon:getAddon", args ?? new GetAddonInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAddonArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the addon.
        /// </summary>
        [Input("addonName", required: true)]
        public string AddonName { get; set; } = null!;

        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("clusterId", required: true)]
        public string ClusterId { get; set; } = null!;

        public GetAddonArgs()
        {
        }
        public static new GetAddonArgs Empty => new GetAddonArgs();
    }

    public sealed class GetAddonInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the addon.
        /// </summary>
        [Input("addonName", required: true)]
        public Input<string> AddonName { get; set; } = null!;

        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        [Input("clusterId", required: true)]
        public Input<string> ClusterId { get; set; } = null!;

        public GetAddonInvokeArgs()
        {
        }
        public static new GetAddonInvokeArgs Empty => new GetAddonInvokeArgs();
    }


    [OutputType]
    public sealed class GetAddonResult
    {
        /// <summary>
        /// The error info of the addon.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddonAddonErrorResult> AddonErrors;
        /// <summary>
        /// The name of the addon.
        /// </summary>
        public readonly string AddonName;
        public readonly string ClusterId;
        /// <summary>
        /// Addon configuration details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddonConfigurationResult> Configurations;
        /// <summary>
        /// current installed version of the addon
        /// </summary>
        public readonly string CurrentInstalledVersion;
        public readonly string Id;
        public readonly bool RemoveAddonResourcesOnDelete;
        /// <summary>
        /// The state of the addon.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the cluster was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// selected addon version, or null indicates autoUpdate
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetAddonResult(
            ImmutableArray<Outputs.GetAddonAddonErrorResult> addonErrors,

            string addonName,

            string clusterId,

            ImmutableArray<Outputs.GetAddonConfigurationResult> configurations,

            string currentInstalledVersion,

            string id,

            bool removeAddonResourcesOnDelete,

            string state,

            string timeCreated,

            string version)
        {
            AddonErrors = addonErrors;
            AddonName = addonName;
            ClusterId = clusterId;
            Configurations = configurations;
            CurrentInstalledVersion = currentInstalledVersion;
            Id = id;
            RemoveAddonResourcesOnDelete = removeAddonResourcesOnDelete;
            State = state;
            TimeCreated = timeCreated;
            Version = version;
        }
    }
}