// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetSecurityPolicyDeploymentSecurityPolicyEntryStates
    {
        /// <summary>
        /// This data source provides the list of Security Policy Deployment Security Policy Entry States in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all security policy entry states in Data Safe.
        /// 
        /// The ListSecurityPolicyEntryStates operation returns only the security policy entry states for the specified security policy entry.
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
        ///     var testSecurityPolicyDeploymentSecurityPolicyEntryStates = Oci.DataSafe.GetSecurityPolicyDeploymentSecurityPolicyEntryStates.Invoke(new()
        ///     {
        ///         SecurityPolicyDeploymentId = testSecurityPolicyDeployment.Id,
        ///         DeploymentStatus = securityPolicyDeploymentSecurityPolicyEntryStateDeploymentStatus,
        ///         SecurityPolicyEntryId = testSecurityPolicyEntry.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult> InvokeAsync(GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult>("oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryStates:getSecurityPolicyDeploymentSecurityPolicyEntryStates", args ?? new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Policy Deployment Security Policy Entry States in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all security policy entry states in Data Safe.
        /// 
        /// The ListSecurityPolicyEntryStates operation returns only the security policy entry states for the specified security policy entry.
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
        ///     var testSecurityPolicyDeploymentSecurityPolicyEntryStates = Oci.DataSafe.GetSecurityPolicyDeploymentSecurityPolicyEntryStates.Invoke(new()
        ///     {
        ///         SecurityPolicyDeploymentId = testSecurityPolicyDeployment.Id,
        ///         DeploymentStatus = securityPolicyDeploymentSecurityPolicyEntryStateDeploymentStatus,
        ///         SecurityPolicyEntryId = testSecurityPolicyEntry.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult> Invoke(GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult>("oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryStates:getSecurityPolicyDeploymentSecurityPolicyEntryStates", args ?? new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Security Policy Deployment Security Policy Entry States in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Retrieves a list of all security policy entry states in Data Safe.
        /// 
        /// The ListSecurityPolicyEntryStates operation returns only the security policy entry states for the specified security policy entry.
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
        ///     var testSecurityPolicyDeploymentSecurityPolicyEntryStates = Oci.DataSafe.GetSecurityPolicyDeploymentSecurityPolicyEntryStates.Invoke(new()
        ///     {
        ///         SecurityPolicyDeploymentId = testSecurityPolicyDeployment.Id,
        ///         DeploymentStatus = securityPolicyDeploymentSecurityPolicyEntryStateDeploymentStatus,
        ///         SecurityPolicyEntryId = testSecurityPolicyEntry.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult> Invoke(GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult>("oci:DataSafe/getSecurityPolicyDeploymentSecurityPolicyEntryStates:getSecurityPolicyDeploymentSecurityPolicyEntryStates", args ?? new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The current state of the security policy deployment.
        /// </summary>
        [Input("deploymentStatus")]
        public string? DeploymentStatus { get; set; }

        [Input("filters")]
        private List<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgs>? _filters;
        public List<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the security policy deployment resource.
        /// </summary>
        [Input("securityPolicyDeploymentId", required: true)]
        public string SecurityPolicyDeploymentId { get; set; } = null!;

        /// <summary>
        /// An optional filter to return only resources that match the specified security policy entry OCID.
        /// </summary>
        [Input("securityPolicyEntryId")]
        public string? SecurityPolicyEntryId { get; set; }

        public GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs()
        {
        }
        public static new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs Empty => new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesArgs();
    }

    public sealed class GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The current state of the security policy deployment.
        /// </summary>
        [Input("deploymentStatus")]
        public Input<string>? DeploymentStatus { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the security policy deployment resource.
        /// </summary>
        [Input("securityPolicyDeploymentId", required: true)]
        public Input<string> SecurityPolicyDeploymentId { get; set; } = null!;

        /// <summary>
        /// An optional filter to return only resources that match the specified security policy entry OCID.
        /// </summary>
        [Input("securityPolicyEntryId")]
        public Input<string>? SecurityPolicyEntryId { get; set; }

        public GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs()
        {
        }
        public static new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs Empty => new GetSecurityPolicyDeploymentSecurityPolicyEntryStatesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult
    {
        /// <summary>
        /// The current deployment status of the security policy deployment and the security policy entry associated.
        /// </summary>
        public readonly string? DeploymentStatus;
        public readonly ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the security policy deployment associated.
        /// </summary>
        public readonly string SecurityPolicyDeploymentId;
        /// <summary>
        /// The OCID of the security policy entry type associated.
        /// </summary>
        public readonly string? SecurityPolicyEntryId;
        /// <summary>
        /// The list of security_policy_entry_state_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionResult> SecurityPolicyEntryStateCollections;

        [OutputConstructor]
        private GetSecurityPolicyDeploymentSecurityPolicyEntryStatesResult(
            string? deploymentStatus,

            ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesFilterResult> filters,

            string id,

            string securityPolicyDeploymentId,

            string? securityPolicyEntryId,

            ImmutableArray<Outputs.GetSecurityPolicyDeploymentSecurityPolicyEntryStatesSecurityPolicyEntryStateCollectionResult> securityPolicyEntryStateCollections)
        {
            DeploymentStatus = deploymentStatus;
            Filters = filters;
            Id = id;
            SecurityPolicyDeploymentId = securityPolicyDeploymentId;
            SecurityPolicyEntryId = securityPolicyEntryId;
            SecurityPolicyEntryStateCollections = securityPolicyEntryStateCollections;
        }
    }
}
