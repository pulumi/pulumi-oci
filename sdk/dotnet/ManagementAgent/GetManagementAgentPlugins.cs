// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ManagementAgent
{
    public static class GetManagementAgentPlugins
    {
        /// <summary>
        /// This data source provides the list of Management Agent Plugins in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Returns a list of managementAgentPlugins.
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
        ///     var testManagementAgentPlugins = Oci.ManagementAgent.GetManagementAgentPlugins.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AgentId = managementAgentId,
        ///         DisplayName = managementAgentPluginDisplayName,
        ///         PlatformTypes = managementAgentPluginPlatformType,
        ///         State = managementAgentPluginState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetManagementAgentPluginsResult> InvokeAsync(GetManagementAgentPluginsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetManagementAgentPluginsResult>("oci:ManagementAgent/getManagementAgentPlugins:getManagementAgentPlugins", args ?? new GetManagementAgentPluginsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Management Agent Plugins in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Returns a list of managementAgentPlugins.
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
        ///     var testManagementAgentPlugins = Oci.ManagementAgent.GetManagementAgentPlugins.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AgentId = managementAgentId,
        ///         DisplayName = managementAgentPluginDisplayName,
        ///         PlatformTypes = managementAgentPluginPlatformType,
        ///         State = managementAgentPluginState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementAgentPluginsResult> Invoke(GetManagementAgentPluginsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementAgentPluginsResult>("oci:ManagementAgent/getManagementAgentPlugins:getManagementAgentPlugins", args ?? new GetManagementAgentPluginsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Management Agent Plugins in Oracle Cloud Infrastructure Management Agent service.
        /// 
        /// Returns a list of managementAgentPlugins.
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
        ///     var testManagementAgentPlugins = Oci.ManagementAgent.GetManagementAgentPlugins.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AgentId = managementAgentId,
        ///         DisplayName = managementAgentPluginDisplayName,
        ///         PlatformTypes = managementAgentPluginPlatformType,
        ///         State = managementAgentPluginState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetManagementAgentPluginsResult> Invoke(GetManagementAgentPluginsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetManagementAgentPluginsResult>("oci:ManagementAgent/getManagementAgentPlugins:getManagementAgentPlugins", args ?? new GetManagementAgentPluginsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetManagementAgentPluginsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ManagementAgentID of the agent from which the Management Agents to be filtered.
        /// </summary>
        [Input("agentId")]
        public string? AgentId { get; set; }

        /// <summary>
        /// The OCID of the compartment to which a request will be scoped.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Filter to return only Management Agent Plugins having the particular display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetManagementAgentPluginsFilterArgs>? _filters;
        public List<Inputs.GetManagementAgentPluginsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetManagementAgentPluginsFilterArgs>());
            set => _filters = value;
        }

        [Input("platformTypes")]
        private List<string>? _platformTypes;

        /// <summary>
        /// Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
        /// </summary>
        public List<string> PlatformTypes
        {
            get => _platformTypes ?? (_platformTypes = new List<string>());
            set => _platformTypes = value;
        }

        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetManagementAgentPluginsArgs()
        {
        }
        public static new GetManagementAgentPluginsArgs Empty => new GetManagementAgentPluginsArgs();
    }

    public sealed class GetManagementAgentPluginsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ManagementAgentID of the agent from which the Management Agents to be filtered.
        /// </summary>
        [Input("agentId")]
        public Input<string>? AgentId { get; set; }

        /// <summary>
        /// The OCID of the compartment to which a request will be scoped.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Filter to return only Management Agent Plugins having the particular display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetManagementAgentPluginsFilterInputArgs>? _filters;
        public InputList<Inputs.GetManagementAgentPluginsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetManagementAgentPluginsFilterInputArgs>());
            set => _filters = value;
        }

        [Input("platformTypes")]
        private InputList<string>? _platformTypes;

        /// <summary>
        /// Array of PlatformTypes to return only results having the particular platform types. Example: ["LINUX"]
        /// </summary>
        public InputList<string> PlatformTypes
        {
            get => _platformTypes ?? (_platformTypes = new InputList<string>());
            set => _platformTypes = value;
        }

        /// <summary>
        /// Filter to return only Management Agents in the particular lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetManagementAgentPluginsInvokeArgs()
        {
        }
        public static new GetManagementAgentPluginsInvokeArgs Empty => new GetManagementAgentPluginsInvokeArgs();
    }


    [OutputType]
    public sealed class GetManagementAgentPluginsResult
    {
        public readonly string? AgentId;
        public readonly string CompartmentId;
        /// <summary>
        /// Management Agent Plugin Display Name
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetManagementAgentPluginsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of management_agent_plugins.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagementAgentPluginsManagementAgentPluginResult> ManagementAgentPlugins;
        public readonly ImmutableArray<string> PlatformTypes;
        /// <summary>
        /// The current state of Management Agent Plugin
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetManagementAgentPluginsResult(
            string? agentId,

            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetManagementAgentPluginsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetManagementAgentPluginsManagementAgentPluginResult> managementAgentPlugins,

            ImmutableArray<string> platformTypes,

            string? state)
        {
            AgentId = agentId;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ManagementAgentPlugins = managementAgentPlugins;
            PlatformTypes = platformTypes;
            State = state;
        }
    }
}
