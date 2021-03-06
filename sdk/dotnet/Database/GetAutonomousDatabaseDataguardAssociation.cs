// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabaseDataguardAssociation
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets an Autonomous Database dataguard assocation for the specified Autonomous Database.
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
        ///         var testAutonomousDatabaseDataguardAssociation = Output.Create(Oci.Database.GetAutonomousDatabaseDataguardAssociation.InvokeAsync(new Oci.Database.GetAutonomousDatabaseDataguardAssociationArgs
        ///         {
        ///             AutonomousDatabaseDataguardAssociationId = oci_database_autonomous_database_dataguard_association.Test_autonomous_database_dataguard_association.Id,
        ///             AutonomousDatabaseId = oci_database_autonomous_database.Test_autonomous_database.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAutonomousDatabaseDataguardAssociationResult> InvokeAsync(GetAutonomousDatabaseDataguardAssociationArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabaseDataguardAssociationResult>("oci:Database/getAutonomousDatabaseDataguardAssociation:getAutonomousDatabaseDataguardAssociation", args ?? new GetAutonomousDatabaseDataguardAssociationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Database Dataguard Association resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets an Autonomous Database dataguard assocation for the specified Autonomous Database.
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
        ///         var testAutonomousDatabaseDataguardAssociation = Output.Create(Oci.Database.GetAutonomousDatabaseDataguardAssociation.InvokeAsync(new Oci.Database.GetAutonomousDatabaseDataguardAssociationArgs
        ///         {
        ///             AutonomousDatabaseDataguardAssociationId = oci_database_autonomous_database_dataguard_association.Test_autonomous_database_dataguard_association.Id,
        ///             AutonomousDatabaseId = oci_database_autonomous_database.Test_autonomous_database.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAutonomousDatabaseDataguardAssociationResult> Invoke(GetAutonomousDatabaseDataguardAssociationInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseDataguardAssociationResult>("oci:Database/getAutonomousDatabaseDataguardAssociation:getAutonomousDatabaseDataguardAssociation", args ?? new GetAutonomousDatabaseDataguardAssociationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDatabaseDataguardAssociationArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseDataguardAssociationId", required: true)]
        public string AutonomousDatabaseDataguardAssociationId { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public string AutonomousDatabaseId { get; set; } = null!;

        public GetAutonomousDatabaseDataguardAssociationArgs()
        {
        }
    }

    public sealed class GetAutonomousDatabaseDataguardAssociationInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The Autonomous Database Dataguard Association [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseDataguardAssociationId", required: true)]
        public Input<string> AutonomousDatabaseDataguardAssociationId { get; set; } = null!;

        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public Input<string> AutonomousDatabaseId { get; set; } = null!;

        public GetAutonomousDatabaseDataguardAssociationInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAutonomousDatabaseDataguardAssociationResult
    {
        /// <summary>
        /// The lag time between updates to the primary database and application of the redo data on the standby database, as computed by the reporting database.  Example: `9 seconds`
        /// </summary>
        public readonly string ApplyLag;
        /// <summary>
        /// The rate at which redo logs are synced between the associated databases.  Example: `180 Mb per second`
        /// </summary>
        public readonly string ApplyRate;
        public readonly string AutonomousDatabaseDataguardAssociationId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database that has a relationship with the peer Autonomous Database.
        /// </summary>
        public readonly string AutonomousDatabaseId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Additional information about the current lifecycleState, if available.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the peer Autonomous Database.
        /// </summary>
        public readonly string PeerAutonomousDatabaseId;
        /// <summary>
        /// The current state of the Autonomous Dataguard.
        /// </summary>
        public readonly string PeerAutonomousDatabaseLifeCycleState;
        /// <summary>
        /// The role of the Autonomous Dataguard enabled Autonomous Container Database.
        /// </summary>
        public readonly string PeerRole;
        /// <summary>
        /// The protection mode of this Data Guard association. For more information, see [Oracle Data Guard Protection Modes](http://docs.oracle.com/database/122/SBYDB/oracle-data-guard-protection-modes.htm#SBYDB02000) in the Oracle Data Guard documentation.
        /// </summary>
        public readonly string ProtectionMode;
        /// <summary>
        /// The role of the Autonomous Dataguard enabled Autonomous Container Database.
        /// </summary>
        public readonly string Role;
        /// <summary>
        /// The current state of the Autonomous Dataguard.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the Data Guard association was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time when the last role change action happened.
        /// </summary>
        public readonly string TimeLastRoleChanged;

        [OutputConstructor]
        private GetAutonomousDatabaseDataguardAssociationResult(
            string applyLag,

            string applyRate,

            string autonomousDatabaseDataguardAssociationId,

            string autonomousDatabaseId,

            string id,

            string lifecycleDetails,

            string peerAutonomousDatabaseId,

            string peerAutonomousDatabaseLifeCycleState,

            string peerRole,

            string protectionMode,

            string role,

            string state,

            string timeCreated,

            string timeLastRoleChanged)
        {
            ApplyLag = applyLag;
            ApplyRate = applyRate;
            AutonomousDatabaseDataguardAssociationId = autonomousDatabaseDataguardAssociationId;
            AutonomousDatabaseId = autonomousDatabaseId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            PeerAutonomousDatabaseId = peerAutonomousDatabaseId;
            PeerAutonomousDatabaseLifeCycleState = peerAutonomousDatabaseLifeCycleState;
            PeerRole = peerRole;
            ProtectionMode = protectionMode;
            Role = role;
            State = state;
            TimeCreated = timeCreated;
            TimeLastRoleChanged = timeLastRoleChanged;
        }
    }
}
