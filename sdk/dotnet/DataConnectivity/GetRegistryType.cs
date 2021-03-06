// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity
{
    public static class GetRegistryType
    {
        /// <summary>
        /// This data source provides details about a specific Registry Type resource in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// This endpoint retrieves dataAsset and connection attributes from DataAssetRegistry
        /// 
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
        ///         var testRegistryType = Output.Create(Oci.DataConnectivity.GetRegistryType.InvokeAsync(new Oci.DataConnectivity.GetRegistryTypeArgs
        ///         {
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///             TypeKey = @var.Registry_type_type_key,
        ///             Fields = @var.Registry_type_fields,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetRegistryTypeResult> InvokeAsync(GetRegistryTypeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetRegistryTypeResult>("oci:DataConnectivity/getRegistryType:getRegistryType", args ?? new GetRegistryTypeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Registry Type resource in Oracle Cloud Infrastructure Data Connectivity service.
        /// 
        /// This endpoint retrieves dataAsset and connection attributes from DataAssetRegistry
        /// 
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
        ///         var testRegistryType = Output.Create(Oci.DataConnectivity.GetRegistryType.InvokeAsync(new Oci.DataConnectivity.GetRegistryTypeArgs
        ///         {
        ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
        ///             TypeKey = @var.Registry_type_type_key,
        ///             Fields = @var.Registry_type_fields,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetRegistryTypeResult> Invoke(GetRegistryTypeInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetRegistryTypeResult>("oci:DataConnectivity/getRegistryType:getRegistryType", args ?? new GetRegistryTypeInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRegistryTypeArgs : Pulumi.InvokeArgs
    {
        [Input("fields")]
        private List<string>? _fields;

        /// <summary>
        /// Specifies the fields to get for an object.
        /// </summary>
        public List<string> Fields
        {
            get => _fields ?? (_fields = new List<string>());
            set => _fields = value;
        }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public string RegistryId { get; set; } = null!;

        /// <summary>
        /// key of the a specefic Type.
        /// </summary>
        [Input("typeKey", required: true)]
        public string TypeKey { get; set; } = null!;

        public GetRegistryTypeArgs()
        {
        }
    }

    public sealed class GetRegistryTypeInvokeArgs : Pulumi.InvokeArgs
    {
        [Input("fields")]
        private InputList<string>? _fields;

        /// <summary>
        /// Specifies the fields to get for an object.
        /// </summary>
        public InputList<string> Fields
        {
            get => _fields ?? (_fields = new InputList<string>());
            set => _fields = value;
        }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public Input<string> RegistryId { get; set; } = null!;

        /// <summary>
        /// key of the a specefic Type.
        /// </summary>
        [Input("typeKey", required: true)]
        public Input<string> TypeKey { get; set; } = null!;

        public GetRegistryTypeInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetRegistryTypeResult
    {
        /// <summary>
        /// Map of connectionType as key and List of attributes as value
        /// </summary>
        public readonly ImmutableDictionary<string, object> ConnectionAttributes;
        /// <summary>
        /// list of attributes for the dataAsset
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryTypeDataAssetAttributeResult> DataAssetAttributes;
        public readonly ImmutableArray<string> Fields;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string RegistryId;
        public readonly string TypeKey;

        [OutputConstructor]
        private GetRegistryTypeResult(
            ImmutableDictionary<string, object> connectionAttributes,

            ImmutableArray<Outputs.GetRegistryTypeDataAssetAttributeResult> dataAssetAttributes,

            ImmutableArray<string> fields,

            string id,

            string registryId,

            string typeKey)
        {
            ConnectionAttributes = connectionAttributes;
            DataAssetAttributes = dataAssetAttributes;
            Fields = fields;
            Id = id;
            RegistryId = registryId;
            TypeKey = typeKey;
        }
    }
}
