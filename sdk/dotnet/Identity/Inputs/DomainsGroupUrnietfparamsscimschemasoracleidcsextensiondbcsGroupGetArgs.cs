// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) DBCS Domain-level schema-name.  This attribute refers implicitly to a value of 'domainLevelSchemaNames' for a particular DB Domain.
        /// </summary>
        [Input("domainLevelSchema")]
        public Input<string>? DomainLevelSchema { get; set; }

        [Input("domainLevelSchemaNames")]
        private InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameGetArgs>? _domainLevelSchemaNames;

        /// <summary>
        /// (Updatable) DBCS Domain-level schema-names. Each value is specific to a DB Domain.
        /// </summary>
        public InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameGetArgs> DomainLevelSchemaNames
        {
            get => _domainLevelSchemaNames ?? (_domainLevelSchemaNames = new InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupDomainLevelSchemaNameGetArgs>());
            set => _domainLevelSchemaNames = value;
        }

        /// <summary>
        /// (Updatable) DBCS instance-level schema-name. This attribute refers implicitly to a value of 'instanceLevelSchemaNames' for a particular DB Instance.
        /// </summary>
        [Input("instanceLevelSchema")]
        public Input<string>? InstanceLevelSchema { get; set; }

        [Input("instanceLevelSchemaNames")]
        private InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaNameGetArgs>? _instanceLevelSchemaNames;

        /// <summary>
        /// (Updatable) DBCS instance-level schema-names. Each schema-name is specific to a DB Instance.
        /// </summary>
        public InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaNameGetArgs> InstanceLevelSchemaNames
        {
            get => _instanceLevelSchemaNames ?? (_instanceLevelSchemaNames = new InputList<Inputs.DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupInstanceLevelSchemaNameGetArgs>());
            set => _instanceLevelSchemaNames = value;
        }

        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupGetArgs()
        {
        }
        public static new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupGetArgs Empty => new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiondbcsGroupGetArgs();
    }
}