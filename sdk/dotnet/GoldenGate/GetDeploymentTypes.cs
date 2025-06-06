// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetDeploymentTypes
    {
        /// <summary>
        /// This data source provides the list of Deployment Types in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Returns an array of DeploymentTypeDescriptor
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
        ///     var testDeploymentTypes = Oci.GoldenGate.GetDeploymentTypes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeploymentType = deploymentTypeDeploymentType,
        ///         DisplayName = deploymentTypeDisplayName,
        ///         OggVersion = deploymentTypeOggVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDeploymentTypesResult> InvokeAsync(GetDeploymentTypesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDeploymentTypesResult>("oci:GoldenGate/getDeploymentTypes:getDeploymentTypes", args ?? new GetDeploymentTypesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Deployment Types in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Returns an array of DeploymentTypeDescriptor
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
        ///     var testDeploymentTypes = Oci.GoldenGate.GetDeploymentTypes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeploymentType = deploymentTypeDeploymentType,
        ///         DisplayName = deploymentTypeDisplayName,
        ///         OggVersion = deploymentTypeOggVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentTypesResult> Invoke(GetDeploymentTypesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentTypesResult>("oci:GoldenGate/getDeploymentTypes:getDeploymentTypes", args ?? new GetDeploymentTypesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Deployment Types in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Returns an array of DeploymentTypeDescriptor
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
        ///     var testDeploymentTypes = Oci.GoldenGate.GetDeploymentTypes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DeploymentType = deploymentTypeDeploymentType,
        ///         DisplayName = deploymentTypeDisplayName,
        ///         OggVersion = deploymentTypeOggVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDeploymentTypesResult> Invoke(GetDeploymentTypesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDeploymentTypesResult>("oci:GoldenGate/getDeploymentTypes:getDeploymentTypes", args ?? new GetDeploymentTypesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDeploymentTypesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The type of deployment, the value determines the exact 'type' of the service executed in the deployment. Default value is DATABASE_ORACLE.
        /// </summary>
        [Input("deploymentType")]
        public string? DeploymentType { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDeploymentTypesFilterArgs>? _filters;
        public List<Inputs.GetDeploymentTypesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDeploymentTypesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Allows to query by a specific GoldenGate version.
        /// </summary>
        [Input("oggVersion")]
        public string? OggVersion { get; set; }

        public GetDeploymentTypesArgs()
        {
        }
        public static new GetDeploymentTypesArgs Empty => new GetDeploymentTypesArgs();
    }

    public sealed class GetDeploymentTypesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment that contains the work request. Work requests should be scoped  to the same compartment as the resource the work request affects. If the work request concerns  multiple resources, and those resources are not in the same compartment, it is up to the service team  to pick the primary resource whose compartment should be used.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The type of deployment, the value determines the exact 'type' of the service executed in the deployment. Default value is DATABASE_ORACLE.
        /// </summary>
        [Input("deploymentType")]
        public Input<string>? DeploymentType { get; set; }

        /// <summary>
        /// A filter to return only the resources that match the entire 'displayName' given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDeploymentTypesFilterInputArgs>? _filters;
        public InputList<Inputs.GetDeploymentTypesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDeploymentTypesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Allows to query by a specific GoldenGate version.
        /// </summary>
        [Input("oggVersion")]
        public Input<string>? OggVersion { get; set; }

        public GetDeploymentTypesInvokeArgs()
        {
        }
        public static new GetDeploymentTypesInvokeArgs Empty => new GetDeploymentTypesInvokeArgs();
    }


    [OutputType]
    public sealed class GetDeploymentTypesResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The type of deployment, which can be any one of the Allowed values.  NOTE: Use of the value 'OGG' is maintained for backward compatibility purposes.  Its use is discouraged in favor of 'DATABASE_ORACLE'.
        /// </summary>
        public readonly string? DeploymentType;
        /// <summary>
        /// The list of deployment_type_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDeploymentTypesDeploymentTypeCollectionResult> DeploymentTypeCollections;
        /// <summary>
        /// An object's Display Name.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetDeploymentTypesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Version of OGG
        /// </summary>
        public readonly string? OggVersion;

        [OutputConstructor]
        private GetDeploymentTypesResult(
            string compartmentId,

            string? deploymentType,

            ImmutableArray<Outputs.GetDeploymentTypesDeploymentTypeCollectionResult> deploymentTypeCollections,

            string? displayName,

            ImmutableArray<Outputs.GetDeploymentTypesFilterResult> filters,

            string id,

            string? oggVersion)
        {
            CompartmentId = compartmentId;
            DeploymentType = deploymentType;
            DeploymentTypeCollections = deploymentTypeCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OggVersion = oggVersion;
        }
    }
}
