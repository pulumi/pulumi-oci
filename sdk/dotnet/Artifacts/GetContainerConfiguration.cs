// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Artifacts
{
    public static class GetContainerConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Container Configuration resource in Oracle Cloud Infrastructure Artifacts service.
        /// 
        /// Get container configuration.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testContainerConfiguration = Output.Create(Oci.Artifacts.GetContainerConfiguration.InvokeAsync(new Oci.Artifacts.GetContainerConfigurationArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetContainerConfigurationResult> InvokeAsync(GetContainerConfigurationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetContainerConfigurationResult>("oci:Artifacts/getContainerConfiguration:getContainerConfiguration", args ?? new GetContainerConfigurationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Container Configuration resource in Oracle Cloud Infrastructure Artifacts service.
        /// 
        /// Get container configuration.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testContainerConfiguration = Output.Create(Oci.Artifacts.GetContainerConfiguration.InvokeAsync(new Oci.Artifacts.GetContainerConfigurationArgs
        ///         {
        ///             CompartmentId = @var.Compartment_id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetContainerConfigurationResult> Invoke(GetContainerConfigurationInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetContainerConfigurationResult>("oci:Artifacts/getContainerConfiguration:getContainerConfiguration", args ?? new GetContainerConfigurationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetContainerConfigurationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        public GetContainerConfigurationArgs()
        {
        }
    }

    public sealed class GetContainerConfigurationInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        public GetContainerConfigurationInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetContainerConfigurationResult
    {
        public readonly string CompartmentId;
        public readonly string Id;
        /// <summary>
        /// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
        /// </summary>
        public readonly bool IsRepositoryCreatedOnFirstPush;
        /// <summary>
        /// The tenancy namespace used in the container repository path.
        /// </summary>
        public readonly string Namespace;

        [OutputConstructor]
        private GetContainerConfigurationResult(
            string compartmentId,

            string id,

            bool isRepositoryCreatedOnFirstPush,

            string @namespace)
        {
            CompartmentId = compartmentId;
            Id = id;
            IsRepositoryCreatedOnFirstPush = isRepositoryCreatedOnFirstPush;
            Namespace = @namespace;
        }
    }
}
