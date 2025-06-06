// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Inputs
{

    public sealed class ManagedDatabaseDbmgmtFeatureConfigArgs : global::Pulumi.ResourceArgs
    {
        [Input("connectorDetails")]
        private InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs>? _connectorDetails;

        /// <summary>
        /// The connector details required to connect to an Oracle cloud database.
        /// </summary>
        public InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs> ConnectorDetails
        {
            get => _connectorDetails ?? (_connectorDetails = new InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigConnectorDetailArgs>());
            set => _connectorDetails = value;
        }

        [Input("databaseConnectionDetails")]
        private InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs>? _databaseConnectionDetails;

        /// <summary>
        /// The connection details required to connect to the database.
        /// </summary>
        public InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs> DatabaseConnectionDetails
        {
            get => _databaseConnectionDetails ?? (_databaseConnectionDetails = new InputList<Inputs.ManagedDatabaseDbmgmtFeatureConfigDatabaseConnectionDetailArgs>());
            set => _databaseConnectionDetails = value;
        }

        /// <summary>
        /// The name of the Database Management feature.
        /// </summary>
        [Input("feature")]
        public Input<string>? Feature { get; set; }

        /// <summary>
        /// The list of statuses for Database Management features.
        /// </summary>
        [Input("featureStatus")]
        public Input<string>? FeatureStatus { get; set; }

        /// <summary>
        /// The Oracle license model that applies to the external database.
        /// </summary>
        [Input("licenseModel")]
        public Input<string>? LicenseModel { get; set; }

        public ManagedDatabaseDbmgmtFeatureConfigArgs()
        {
        }
        public static new ManagedDatabaseDbmgmtFeatureConfigArgs Empty => new ManagedDatabaseDbmgmtFeatureConfigArgs();
    }
}
