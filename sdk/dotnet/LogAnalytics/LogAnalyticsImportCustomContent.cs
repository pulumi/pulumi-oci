// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    /// <summary>
    /// This resource provides the Log Analytics Import Custom Content resource in Oracle Cloud Infrastructure Log Analytics service.
    /// 
    /// Imports the specified custom content from the input in zip format.
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
    ///     var testLogAnalyticsImportCustomContent = new Oci.LogAnalytics.LogAnalyticsImportCustomContent("test_log_analytics_import_custom_content", new()
    ///     {
    ///         ImportCustomContentFile = logAnalyticsImportCustomContentImportCustomContentFile,
    ///         Namespace = logAnalyticsImportCustomContentNamespace,
    ///         Expect = logAnalyticsImportCustomContentExpect,
    ///         IsOverwrite = logAnalyticsImportCustomContentIsOverwrite,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for LogAnalyticsImportCustomContent
    /// </summary>
    [OciResourceType("oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent")]
    public partial class LogAnalyticsImportCustomContent : global::Pulumi.CustomResource
    {
        /// <summary>
        /// LogAnalyticsImportCustomChangeList
        /// </summary>
        [Output("changeLists")]
        public Output<ImmutableArray<Outputs.LogAnalyticsImportCustomContentChangeList>> ChangeLists { get; private set; } = null!;

        /// <summary>
        /// The content name.
        /// </summary>
        [Output("contentName")]
        public Output<string> ContentName { get; private set; } = null!;

        /// <summary>
        /// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("expect")]
        public Output<string> Expect { get; private set; } = null!;

        /// <summary>
        /// The field names.
        /// </summary>
        [Output("fieldNames")]
        public Output<ImmutableArray<string>> FieldNames { get; private set; } = null!;

        /// <summary>
        /// Path to the file to upload which contains the custom content.
        /// </summary>
        [Output("importCustomContentFile")]
        public Output<string> ImportCustomContentFile { get; private set; } = null!;

        /// <summary>
        /// A flag indicating whether or not to overwrite existing content if a conflict is found during import content operation.
        /// </summary>
        [Output("isOverwrite")]
        public Output<bool> IsOverwrite { get; private set; } = null!;

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;

        /// <summary>
        /// The parser names.
        /// </summary>
        [Output("parserNames")]
        public Output<ImmutableArray<string>> ParserNames { get; private set; } = null!;

        /// <summary>
        /// The source names.
        /// </summary>
        [Output("sourceNames")]
        public Output<ImmutableArray<string>> SourceNames { get; private set; } = null!;


        /// <summary>
        /// Create a LogAnalyticsImportCustomContent resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LogAnalyticsImportCustomContent(string name, LogAnalyticsImportCustomContentArgs args, CustomResourceOptions? options = null)
            : base("oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent", name, args ?? new LogAnalyticsImportCustomContentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LogAnalyticsImportCustomContent(string name, Input<string> id, LogAnalyticsImportCustomContentState? state = null, CustomResourceOptions? options = null)
            : base("oci:LogAnalytics/logAnalyticsImportCustomContent:LogAnalyticsImportCustomContent", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing LogAnalyticsImportCustomContent resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LogAnalyticsImportCustomContent Get(string name, Input<string> id, LogAnalyticsImportCustomContentState? state = null, CustomResourceOptions? options = null)
        {
            return new LogAnalyticsImportCustomContent(name, id, state, options);
        }
    }

    public sealed class LogAnalyticsImportCustomContentArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("expect")]
        public Input<string>? Expect { get; set; }

        /// <summary>
        /// Path to the file to upload which contains the custom content.
        /// </summary>
        [Input("importCustomContentFile", required: true)]
        public Input<string> ImportCustomContentFile { get; set; } = null!;

        /// <summary>
        /// A flag indicating whether or not to overwrite existing content if a conflict is found during import content operation.
        /// </summary>
        [Input("isOverwrite")]
        public Input<bool>? IsOverwrite { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        public LogAnalyticsImportCustomContentArgs()
        {
        }
        public static new LogAnalyticsImportCustomContentArgs Empty => new LogAnalyticsImportCustomContentArgs();
    }

    public sealed class LogAnalyticsImportCustomContentState : global::Pulumi.ResourceArgs
    {
        [Input("changeLists")]
        private InputList<Inputs.LogAnalyticsImportCustomContentChangeListGetArgs>? _changeLists;

        /// <summary>
        /// LogAnalyticsImportCustomChangeList
        /// </summary>
        public InputList<Inputs.LogAnalyticsImportCustomContentChangeListGetArgs> ChangeLists
        {
            get => _changeLists ?? (_changeLists = new InputList<Inputs.LogAnalyticsImportCustomContentChangeListGetArgs>());
            set => _changeLists = value;
        }

        /// <summary>
        /// The content name.
        /// </summary>
        [Input("contentName")]
        public Input<string>? ContentName { get; set; }

        /// <summary>
        /// A value of `100-continue` requests preliminary verification of the request method, path, and headers before the request body is sent. If no error results from such verification, the server will send a 100 (Continue) interim response to indicate readiness for the request body. The only allowed value for this parameter is "100-Continue" (case-insensitive).
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("expect")]
        public Input<string>? Expect { get; set; }

        [Input("fieldNames")]
        private InputList<string>? _fieldNames;

        /// <summary>
        /// The field names.
        /// </summary>
        public InputList<string> FieldNames
        {
            get => _fieldNames ?? (_fieldNames = new InputList<string>());
            set => _fieldNames = value;
        }

        /// <summary>
        /// Path to the file to upload which contains the custom content.
        /// </summary>
        [Input("importCustomContentFile")]
        public Input<string>? ImportCustomContentFile { get; set; }

        /// <summary>
        /// A flag indicating whether or not to overwrite existing content if a conflict is found during import content operation.
        /// </summary>
        [Input("isOverwrite")]
        public Input<bool>? IsOverwrite { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        [Input("parserNames")]
        private InputList<string>? _parserNames;

        /// <summary>
        /// The parser names.
        /// </summary>
        public InputList<string> ParserNames
        {
            get => _parserNames ?? (_parserNames = new InputList<string>());
            set => _parserNames = value;
        }

        [Input("sourceNames")]
        private InputList<string>? _sourceNames;

        /// <summary>
        /// The source names.
        /// </summary>
        public InputList<string> SourceNames
        {
            get => _sourceNames ?? (_sourceNames = new InputList<string>());
            set => _sourceNames = value;
        }

        public LogAnalyticsImportCustomContentState()
        {
        }
        public static new LogAnalyticsImportCustomContentState Empty => new LogAnalyticsImportCustomContentState();
    }
}
