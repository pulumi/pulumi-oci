// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeInstanceAgent
{
    public static class GetInstanceAgentPlugin
    {
        /// <summary>
        /// This data source provides details about a specific Instance Agent Plugin resource in Oracle Cloud Infrastructure Compute Instance Agent service.
        /// 
        /// The API to get information for a plugin.
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
        ///     var testInstanceAgentPlugin = Oci.ComputeInstanceAgent.GetInstanceAgentPlugin.Invoke(new()
        ///     {
        ///         InstanceagentId = testInstanceagent.Id,
        ///         PluginName = instanceAgentPluginPluginName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetInstanceAgentPluginResult> InvokeAsync(GetInstanceAgentPluginArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetInstanceAgentPluginResult>("oci:ComputeInstanceAgent/getInstanceAgentPlugin:getInstanceAgentPlugin", args ?? new GetInstanceAgentPluginArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Instance Agent Plugin resource in Oracle Cloud Infrastructure Compute Instance Agent service.
        /// 
        /// The API to get information for a plugin.
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
        ///     var testInstanceAgentPlugin = Oci.ComputeInstanceAgent.GetInstanceAgentPlugin.Invoke(new()
        ///     {
        ///         InstanceagentId = testInstanceagent.Id,
        ///         PluginName = instanceAgentPluginPluginName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetInstanceAgentPluginResult> Invoke(GetInstanceAgentPluginInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetInstanceAgentPluginResult>("oci:ComputeInstanceAgent/getInstanceAgentPlugin:getInstanceAgentPlugin", args ?? new GetInstanceAgentPluginInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Instance Agent Plugin resource in Oracle Cloud Infrastructure Compute Instance Agent service.
        /// 
        /// The API to get information for a plugin.
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
        ///     var testInstanceAgentPlugin = Oci.ComputeInstanceAgent.GetInstanceAgentPlugin.Invoke(new()
        ///     {
        ///         InstanceagentId = testInstanceagent.Id,
        ///         PluginName = instanceAgentPluginPluginName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetInstanceAgentPluginResult> Invoke(GetInstanceAgentPluginInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetInstanceAgentPluginResult>("oci:ComputeInstanceAgent/getInstanceAgentPlugin:getInstanceAgentPlugin", args ?? new GetInstanceAgentPluginInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetInstanceAgentPluginArgs : global::Pulumi.InvokeArgs
    {
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceagentId", required: true)]
        public string InstanceagentId { get; set; } = null!;

        /// <summary>
        /// The name of the plugin.
        /// </summary>
        [Input("pluginName", required: true)]
        public string PluginName { get; set; } = null!;

        public GetInstanceAgentPluginArgs()
        {
        }
        public static new GetInstanceAgentPluginArgs Empty => new GetInstanceAgentPluginArgs();
    }

    public sealed class GetInstanceAgentPluginInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceagentId", required: true)]
        public Input<string> InstanceagentId { get; set; } = null!;

        /// <summary>
        /// The name of the plugin.
        /// </summary>
        [Input("pluginName", required: true)]
        public Input<string> PluginName { get; set; } = null!;

        public GetInstanceAgentPluginInvokeArgs()
        {
        }
        public static new GetInstanceAgentPluginInvokeArgs Empty => new GetInstanceAgentPluginInvokeArgs();
    }


    [OutputType]
    public sealed class GetInstanceAgentPluginResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string InstanceagentId;
        /// <summary>
        /// The optional message from the agent plugin
        /// </summary>
        public readonly string Message;
        /// <summary>
        /// The plugin name
        /// </summary>
        public readonly string Name;
        public readonly string PluginName;
        /// <summary>
        /// The plugin status Specified the plugin state on the instance * `RUNNING` - The plugin is in running state * `STOPPED` - The plugin is in stopped state * `NOT_SUPPORTED` - The plugin is not supported on this platform * `INVALID` - The plugin state is not recognizable by the service
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The last update time of the plugin in UTC
        /// </summary>
        public readonly string TimeLastUpdatedUtc;

        [OutputConstructor]
        private GetInstanceAgentPluginResult(
            string compartmentId,

            string id,

            string instanceagentId,

            string message,

            string name,

            string pluginName,

            string status,

            string timeLastUpdatedUtc)
        {
            CompartmentId = compartmentId;
            Id = id;
            InstanceagentId = instanceagentId;
            Message = message;
            Name = name;
            PluginName = pluginName;
            Status = status;
            TimeLastUpdatedUtc = timeLastUpdatedUtc;
        }
    }
}
