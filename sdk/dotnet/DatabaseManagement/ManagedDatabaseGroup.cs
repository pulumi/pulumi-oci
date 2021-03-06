// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    /// <summary>
    /// This resource provides the Managed Database Group resource in Oracle Cloud Infrastructure Database Management service.
    /// 
    /// Creates a Managed Database Group. The group does not contain any
    /// Managed Databases when it is created, and they must be added later.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testManagedDatabaseGroup = new Oci.DatabaseManagement.ManagedDatabaseGroup("testManagedDatabaseGroup", new Oci.DatabaseManagement.ManagedDatabaseGroupArgs
    ///         {
    ///             CompartmentId = @var.Compartment_id,
    ///             Description = @var.Managed_database_group_description,
    ///             ManagedDatabases = 
    ///             {
    ///                 new Oci.DatabaseManagement.Inputs.ManagedDatabaseGroupManagedDatabaseArgs
    ///                 {
    ///                     Id = @var.Managed_database_id,
    ///                 },
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// ManagedDatabaseGroups can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup test_managed_database_group "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup")]
    public partial class ManagedDatabaseGroup : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The information specified by the user about the Managed Database Group.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
        /// </summary>
        [Output("managedDatabases")]
        public Output<ImmutableArray<Outputs.ManagedDatabaseGroupManagedDatabase>> ManagedDatabases { get; private set; } = null!;

        /// <summary>
        /// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the Managed Database Group.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the Managed Database Group was created.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the Managed Database Group was last updated.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a ManagedDatabaseGroup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public ManagedDatabaseGroup(string name, ManagedDatabaseGroupArgs args, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, args ?? new ManagedDatabaseGroupArgs(), MakeResourceOptions(options, ""))
        {
        }

        private ManagedDatabaseGroup(string name, Input<string> id, ManagedDatabaseGroupState? state = null, CustomResourceOptions? options = null)
            : base("oci:DatabaseManagement/managedDatabaseGroup:ManagedDatabaseGroup", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing ManagedDatabaseGroup resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static ManagedDatabaseGroup Get(string name, Input<string> id, ManagedDatabaseGroupState? state = null, CustomResourceOptions? options = null)
        {
            return new ManagedDatabaseGroup(name, id, state, options);
        }
    }

    public sealed class ManagedDatabaseGroupArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The information specified by the user about the Managed Database Group.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("managedDatabases")]
        private InputList<Inputs.ManagedDatabaseGroupManagedDatabaseArgs>? _managedDatabases;

        /// <summary>
        /// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
        /// </summary>
        public InputList<Inputs.ManagedDatabaseGroupManagedDatabaseArgs> ManagedDatabases
        {
            get => _managedDatabases ?? (_managedDatabases = new InputList<Inputs.ManagedDatabaseGroupManagedDatabaseArgs>());
            set => _managedDatabases = value;
        }

        /// <summary>
        /// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public ManagedDatabaseGroupArgs()
        {
        }
    }

    public sealed class ManagedDatabaseGroupState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// (Updatable) The information specified by the user about the Managed Database Group.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("managedDatabases")]
        private InputList<Inputs.ManagedDatabaseGroupManagedDatabaseGetArgs>? _managedDatabases;

        /// <summary>
        /// (Updatable) Set of Managed Databases that the user wants to add to the Managed Database Group. Specifying a block will add the Managed Database to Managed Database Group and removing the block will remove Managed Database from the Managed Database Group.
        /// </summary>
        public InputList<Inputs.ManagedDatabaseGroupManagedDatabaseGetArgs> ManagedDatabases
        {
            get => _managedDatabases ?? (_managedDatabases = new InputList<Inputs.ManagedDatabaseGroupManagedDatabaseGetArgs>());
            set => _managedDatabases = value;
        }

        /// <summary>
        /// The name of the Managed Database Group. Valid characters are uppercase or lowercase letters, numbers, and "_". The name of the Managed Database Group cannot be modified. It must be unique in the compartment and must begin with an alphabetic character.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The current lifecycle state of the Managed Database Group.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the Managed Database Group was created.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the Managed Database Group was last updated.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public ManagedDatabaseGroupState()
        {
        }
    }
}
