// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Inputs
{

    public sealed class ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the external DB system resides.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        [Input("connectors")]
        private InputList<Inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs>? _connectors;

        /// <summary>
        /// The connector details used to connect to the external DB system component.
        /// </summary>
        public InputList<Inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs> Connectors
        {
            get => _connectors ?? (_connectors = new InputList<Inputs.ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseConnectorArgs>());
            set => _connectors = value;
        }

        /// <summary>
        /// The unique identifier of the parent Container Database (CDB).
        /// </summary>
        [Input("containerDatabaseId")]
        public Input<string>? ContainerDatabaseId { get; set; }

        /// <summary>
        /// The unique identifier of the PDB.
        /// </summary>
        [Input("guid")]
        public Input<string>? Guid { get; set; }

        public ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs()
        {
        }
        public static new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs Empty => new ExternalDbSystemDiscoveryDiscoveredComponentPluggableDatabaseArgs();
    }
}