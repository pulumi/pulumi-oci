// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetMaskingPolicyMaskingObjects
    {
        /// <summary>
        /// This data source provides the list of Masking Policy Masking Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of masking objects present in the specified masking policy and based on the specified query parameters.
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
        ///     var testMaskingPolicyMaskingObjects = Oci.DataSafe.GetMaskingPolicyMaskingObjects.Invoke(new()
        ///     {
        ///         MaskingPolicyId = testMaskingPolicy.Id,
        ///         Objects = maskingPolicyMaskingObjectObject,
        ///         ObjectTypes = maskingPolicyMaskingObjectObjectType,
        ///         SchemaNames = maskingPolicyMaskingObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMaskingPolicyMaskingObjectsResult> InvokeAsync(GetMaskingPolicyMaskingObjectsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMaskingPolicyMaskingObjectsResult>("oci:DataSafe/getMaskingPolicyMaskingObjects:getMaskingPolicyMaskingObjects", args ?? new GetMaskingPolicyMaskingObjectsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Masking Policy Masking Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of masking objects present in the specified masking policy and based on the specified query parameters.
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
        ///     var testMaskingPolicyMaskingObjects = Oci.DataSafe.GetMaskingPolicyMaskingObjects.Invoke(new()
        ///     {
        ///         MaskingPolicyId = testMaskingPolicy.Id,
        ///         Objects = maskingPolicyMaskingObjectObject,
        ///         ObjectTypes = maskingPolicyMaskingObjectObjectType,
        ///         SchemaNames = maskingPolicyMaskingObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMaskingPolicyMaskingObjectsResult> Invoke(GetMaskingPolicyMaskingObjectsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMaskingPolicyMaskingObjectsResult>("oci:DataSafe/getMaskingPolicyMaskingObjects:getMaskingPolicyMaskingObjects", args ?? new GetMaskingPolicyMaskingObjectsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Masking Policy Masking Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of masking objects present in the specified masking policy and based on the specified query parameters.
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
        ///     var testMaskingPolicyMaskingObjects = Oci.DataSafe.GetMaskingPolicyMaskingObjects.Invoke(new()
        ///     {
        ///         MaskingPolicyId = testMaskingPolicy.Id,
        ///         Objects = maskingPolicyMaskingObjectObject,
        ///         ObjectTypes = maskingPolicyMaskingObjectObjectType,
        ///         SchemaNames = maskingPolicyMaskingObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMaskingPolicyMaskingObjectsResult> Invoke(GetMaskingPolicyMaskingObjectsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMaskingPolicyMaskingObjectsResult>("oci:DataSafe/getMaskingPolicyMaskingObjects:getMaskingPolicyMaskingObjects", args ?? new GetMaskingPolicyMaskingObjectsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMaskingPolicyMaskingObjectsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetMaskingPolicyMaskingObjectsFilterArgs>? _filters;
        public List<Inputs.GetMaskingPolicyMaskingObjectsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetMaskingPolicyMaskingObjectsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the masking policy.
        /// </summary>
        [Input("maskingPolicyId", required: true)]
        public string MaskingPolicyId { get; set; } = null!;

        [Input("objectTypes")]
        private List<string>? _objectTypes;

        /// <summary>
        /// A filter to return only items related to a specific object type.
        /// </summary>
        public List<string> ObjectTypes
        {
            get => _objectTypes ?? (_objectTypes = new List<string>());
            set => _objectTypes = value;
        }

        [Input("objects")]
        private List<string>? _objects;

        /// <summary>
        /// A filter to return only items related to a specific object name.
        /// </summary>
        public List<string> Objects
        {
            get => _objects ?? (_objects = new List<string>());
            set => _objects = value;
        }

        [Input("schemaNames")]
        private List<string>? _schemaNames;

        /// <summary>
        /// A filter to return only items related to specific schema name.
        /// </summary>
        public List<string> SchemaNames
        {
            get => _schemaNames ?? (_schemaNames = new List<string>());
            set => _schemaNames = value;
        }

        public GetMaskingPolicyMaskingObjectsArgs()
        {
        }
        public static new GetMaskingPolicyMaskingObjectsArgs Empty => new GetMaskingPolicyMaskingObjectsArgs();
    }

    public sealed class GetMaskingPolicyMaskingObjectsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetMaskingPolicyMaskingObjectsFilterInputArgs>? _filters;
        public InputList<Inputs.GetMaskingPolicyMaskingObjectsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetMaskingPolicyMaskingObjectsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the masking policy.
        /// </summary>
        [Input("maskingPolicyId", required: true)]
        public Input<string> MaskingPolicyId { get; set; } = null!;

        [Input("objectTypes")]
        private InputList<string>? _objectTypes;

        /// <summary>
        /// A filter to return only items related to a specific object type.
        /// </summary>
        public InputList<string> ObjectTypes
        {
            get => _objectTypes ?? (_objectTypes = new InputList<string>());
            set => _objectTypes = value;
        }

        [Input("objects")]
        private InputList<string>? _objects;

        /// <summary>
        /// A filter to return only items related to a specific object name.
        /// </summary>
        public InputList<string> Objects
        {
            get => _objects ?? (_objects = new InputList<string>());
            set => _objects = value;
        }

        [Input("schemaNames")]
        private InputList<string>? _schemaNames;

        /// <summary>
        /// A filter to return only items related to specific schema name.
        /// </summary>
        public InputList<string> SchemaNames
        {
            get => _schemaNames ?? (_schemaNames = new InputList<string>());
            set => _schemaNames = value;
        }

        public GetMaskingPolicyMaskingObjectsInvokeArgs()
        {
        }
        public static new GetMaskingPolicyMaskingObjectsInvokeArgs Empty => new GetMaskingPolicyMaskingObjectsInvokeArgs();
    }


    [OutputType]
    public sealed class GetMaskingPolicyMaskingObjectsResult
    {
        public readonly ImmutableArray<Outputs.GetMaskingPolicyMaskingObjectsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of masking_object_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMaskingPolicyMaskingObjectsMaskingObjectCollectionResult> MaskingObjectCollections;
        public readonly string MaskingPolicyId;
        /// <summary>
        /// The type of the database object that contains the masking column.
        /// </summary>
        public readonly ImmutableArray<string> ObjectTypes;
        /// <summary>
        /// The database object that contains the masking column.
        /// </summary>
        public readonly ImmutableArray<string> Objects;
        /// <summary>
        /// The database schema that contains the masking column.
        /// </summary>
        public readonly ImmutableArray<string> SchemaNames;

        [OutputConstructor]
        private GetMaskingPolicyMaskingObjectsResult(
            ImmutableArray<Outputs.GetMaskingPolicyMaskingObjectsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetMaskingPolicyMaskingObjectsMaskingObjectCollectionResult> maskingObjectCollections,

            string maskingPolicyId,

            ImmutableArray<string> objectTypes,

            ImmutableArray<string> objects,

            ImmutableArray<string> schemaNames)
        {
            Filters = filters;
            Id = id;
            MaskingObjectCollections = maskingObjectCollections;
            MaskingPolicyId = maskingPolicyId;
            ObjectTypes = objectTypes;
            Objects = objects;
            SchemaNames = schemaNames;
        }
    }
}
