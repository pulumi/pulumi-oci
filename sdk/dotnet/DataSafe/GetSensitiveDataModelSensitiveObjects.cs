// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe
{
    public static class GetSensitiveDataModelSensitiveObjects
    {
        /// <summary>
        /// This data source provides the list of Sensitive Data Model Sensitive Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of sensitive objects present in the specified sensitive data model based on the specified query parameters.
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
        ///     var testSensitiveDataModelSensitiveObjects = Oci.DataSafe.GetSensitiveDataModelSensitiveObjects.Invoke(new()
        ///     {
        ///         SensitiveDataModelId = testSensitiveDataModel.Id,
        ///         Objects = sensitiveDataModelSensitiveObjectObject,
        ///         ObjectTypes = sensitiveDataModelSensitiveObjectObjectType,
        ///         SchemaNames = sensitiveDataModelSensitiveObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSensitiveDataModelSensitiveObjectsResult> InvokeAsync(GetSensitiveDataModelSensitiveObjectsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSensitiveDataModelSensitiveObjectsResult>("oci:DataSafe/getSensitiveDataModelSensitiveObjects:getSensitiveDataModelSensitiveObjects", args ?? new GetSensitiveDataModelSensitiveObjectsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Sensitive Data Model Sensitive Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of sensitive objects present in the specified sensitive data model based on the specified query parameters.
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
        ///     var testSensitiveDataModelSensitiveObjects = Oci.DataSafe.GetSensitiveDataModelSensitiveObjects.Invoke(new()
        ///     {
        ///         SensitiveDataModelId = testSensitiveDataModel.Id,
        ///         Objects = sensitiveDataModelSensitiveObjectObject,
        ///         ObjectTypes = sensitiveDataModelSensitiveObjectObjectType,
        ///         SchemaNames = sensitiveDataModelSensitiveObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSensitiveDataModelSensitiveObjectsResult> Invoke(GetSensitiveDataModelSensitiveObjectsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSensitiveDataModelSensitiveObjectsResult>("oci:DataSafe/getSensitiveDataModelSensitiveObjects:getSensitiveDataModelSensitiveObjects", args ?? new GetSensitiveDataModelSensitiveObjectsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Sensitive Data Model Sensitive Objects in Oracle Cloud Infrastructure Data Safe service.
        /// 
        /// Gets a list of sensitive objects present in the specified sensitive data model based on the specified query parameters.
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
        ///     var testSensitiveDataModelSensitiveObjects = Oci.DataSafe.GetSensitiveDataModelSensitiveObjects.Invoke(new()
        ///     {
        ///         SensitiveDataModelId = testSensitiveDataModel.Id,
        ///         Objects = sensitiveDataModelSensitiveObjectObject,
        ///         ObjectTypes = sensitiveDataModelSensitiveObjectObjectType,
        ///         SchemaNames = sensitiveDataModelSensitiveObjectSchemaName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSensitiveDataModelSensitiveObjectsResult> Invoke(GetSensitiveDataModelSensitiveObjectsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSensitiveDataModelSensitiveObjectsResult>("oci:DataSafe/getSensitiveDataModelSensitiveObjects:getSensitiveDataModelSensitiveObjects", args ?? new GetSensitiveDataModelSensitiveObjectsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSensitiveDataModelSensitiveObjectsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetSensitiveDataModelSensitiveObjectsFilterArgs>? _filters;
        public List<Inputs.GetSensitiveDataModelSensitiveObjectsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSensitiveDataModelSensitiveObjectsFilterArgs>());
            set => _filters = value;
        }

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

        /// <summary>
        /// The OCID of the sensitive data model.
        /// </summary>
        [Input("sensitiveDataModelId", required: true)]
        public string SensitiveDataModelId { get; set; } = null!;

        public GetSensitiveDataModelSensitiveObjectsArgs()
        {
        }
        public static new GetSensitiveDataModelSensitiveObjectsArgs Empty => new GetSensitiveDataModelSensitiveObjectsArgs();
    }

    public sealed class GetSensitiveDataModelSensitiveObjectsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetSensitiveDataModelSensitiveObjectsFilterInputArgs>? _filters;
        public InputList<Inputs.GetSensitiveDataModelSensitiveObjectsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSensitiveDataModelSensitiveObjectsFilterInputArgs>());
            set => _filters = value;
        }

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

        /// <summary>
        /// The OCID of the sensitive data model.
        /// </summary>
        [Input("sensitiveDataModelId", required: true)]
        public Input<string> SensitiveDataModelId { get; set; } = null!;

        public GetSensitiveDataModelSensitiveObjectsInvokeArgs()
        {
        }
        public static new GetSensitiveDataModelSensitiveObjectsInvokeArgs Empty => new GetSensitiveDataModelSensitiveObjectsInvokeArgs();
    }


    [OutputType]
    public sealed class GetSensitiveDataModelSensitiveObjectsResult
    {
        public readonly ImmutableArray<Outputs.GetSensitiveDataModelSensitiveObjectsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The type of the database object that contains the sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> ObjectTypes;
        /// <summary>
        /// The database object that contains the sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> Objects;
        /// <summary>
        /// The database schema that contains the sensitive column.
        /// </summary>
        public readonly ImmutableArray<string> SchemaNames;
        public readonly string SensitiveDataModelId;
        /// <summary>
        /// The list of sensitive_object_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSensitiveDataModelSensitiveObjectsSensitiveObjectCollectionResult> SensitiveObjectCollections;

        [OutputConstructor]
        private GetSensitiveDataModelSensitiveObjectsResult(
            ImmutableArray<Outputs.GetSensitiveDataModelSensitiveObjectsFilterResult> filters,

            string id,

            ImmutableArray<string> objectTypes,

            ImmutableArray<string> objects,

            ImmutableArray<string> schemaNames,

            string sensitiveDataModelId,

            ImmutableArray<Outputs.GetSensitiveDataModelSensitiveObjectsSensitiveObjectCollectionResult> sensitiveObjectCollections)
        {
            Filters = filters;
            Id = id;
            ObjectTypes = objectTypes;
            Objects = objects;
            SchemaNames = schemaNames;
            SensitiveDataModelId = sensitiveDataModelId;
            SensitiveObjectCollections = sensitiveObjectCollections;
        }
    }
}
