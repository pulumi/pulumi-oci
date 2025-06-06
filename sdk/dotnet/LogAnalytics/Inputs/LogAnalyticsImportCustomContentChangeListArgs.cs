// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Inputs
{

    public sealed class LogAnalyticsImportCustomContentChangeListArgs : global::Pulumi.ResourceArgs
    {
        [Input("conflictFieldDisplayNames")]
        private InputList<string>? _conflictFieldDisplayNames;

        /// <summary>
        /// A list of field display names with conflicts.
        /// </summary>
        public InputList<string> ConflictFieldDisplayNames
        {
            get => _conflictFieldDisplayNames ?? (_conflictFieldDisplayNames = new InputList<string>());
            set => _conflictFieldDisplayNames = value;
        }

        [Input("conflictParserNames")]
        private InputList<string>? _conflictParserNames;

        /// <summary>
        /// A list of parser names with conflicts.
        /// </summary>
        public InputList<string> ConflictParserNames
        {
            get => _conflictParserNames ?? (_conflictParserNames = new InputList<string>());
            set => _conflictParserNames = value;
        }

        [Input("conflictSourceNames")]
        private InputList<string>? _conflictSourceNames;

        /// <summary>
        /// A list of source names with conflicts.
        /// </summary>
        public InputList<string> ConflictSourceNames
        {
            get => _conflictSourceNames ?? (_conflictSourceNames = new InputList<string>());
            set => _conflictSourceNames = value;
        }

        [Input("createdFieldDisplayNames")]
        private InputList<string>? _createdFieldDisplayNames;

        /// <summary>
        /// An array of created field display names.
        /// </summary>
        public InputList<string> CreatedFieldDisplayNames
        {
            get => _createdFieldDisplayNames ?? (_createdFieldDisplayNames = new InputList<string>());
            set => _createdFieldDisplayNames = value;
        }

        [Input("createdParserNames")]
        private InputList<string>? _createdParserNames;

        /// <summary>
        /// An array of created parser names.
        /// </summary>
        public InputList<string> CreatedParserNames
        {
            get => _createdParserNames ?? (_createdParserNames = new InputList<string>());
            set => _createdParserNames = value;
        }

        [Input("createdSourceNames")]
        private InputList<string>? _createdSourceNames;

        /// <summary>
        /// An array of created source names.
        /// </summary>
        public InputList<string> CreatedSourceNames
        {
            get => _createdSourceNames ?? (_createdSourceNames = new InputList<string>());
            set => _createdSourceNames = value;
        }

        [Input("updatedFieldDisplayNames")]
        private InputList<string>? _updatedFieldDisplayNames;

        /// <summary>
        /// An array of updated field display names.
        /// </summary>
        public InputList<string> UpdatedFieldDisplayNames
        {
            get => _updatedFieldDisplayNames ?? (_updatedFieldDisplayNames = new InputList<string>());
            set => _updatedFieldDisplayNames = value;
        }

        [Input("updatedParserNames")]
        private InputList<string>? _updatedParserNames;

        /// <summary>
        /// An array of updated parser names.
        /// </summary>
        public InputList<string> UpdatedParserNames
        {
            get => _updatedParserNames ?? (_updatedParserNames = new InputList<string>());
            set => _updatedParserNames = value;
        }

        [Input("updatedSourceNames")]
        private InputList<string>? _updatedSourceNames;

        /// <summary>
        /// An array of updated source names.
        /// </summary>
        public InputList<string> UpdatedSourceNames
        {
            get => _updatedSourceNames ?? (_updatedSourceNames = new InputList<string>());
            set => _updatedSourceNames = value;
        }

        public LogAnalyticsImportCustomContentChangeListArgs()
        {
        }
        public static new LogAnalyticsImportCustomContentChangeListArgs Empty => new LogAnalyticsImportCustomContentChangeListArgs();
    }
}
