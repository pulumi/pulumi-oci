// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    /// <summary>
    /// This resource provides the Db Credential resource in Oracle Cloud Infrastructure Identity service.
    /// 
    /// Creates a new DB credential for the specified user.
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
    ///         var testDbCredential = new Oci.Identity.DbCredential("testDbCredential", new Oci.Identity.DbCredentialArgs
    ///         {
    ///             Description = @var.Db_credential_description,
    ///             Password = @var.Db_credential_password,
    ///             UserId = oci_identity_user.Test_user.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// Import is not supported for this resource.
    /// </summary>
    [OciResourceType("oci:Identity/dbCredential:DbCredential")]
    public partial class DbCredential : Pulumi.CustomResource
    {
        /// <summary>
        /// The description you assign to the DB credentials during creation.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Output("lifecycleDetails")]
        public Output<string> LifecycleDetails { get; private set; } = null!;

        /// <summary>
        /// The password for the DB credentials during creation.
        /// </summary>
        [Output("password")]
        public Output<string> Password { get; private set; } = null!;

        /// <summary>
        /// The credential's current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeExpires")]
        public Output<string> TimeExpires { get; private set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Output("userId")]
        public Output<string> UserId { get; private set; } = null!;


        /// <summary>
        /// Create a DbCredential resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public DbCredential(string name, DbCredentialArgs args, CustomResourceOptions? options = null)
            : base("oci:Identity/dbCredential:DbCredential", name, args ?? new DbCredentialArgs(), MakeResourceOptions(options, ""))
        {
        }

        private DbCredential(string name, Input<string> id, DbCredentialState? state = null, CustomResourceOptions? options = null)
            : base("oci:Identity/dbCredential:DbCredential", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing DbCredential resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static DbCredential Get(string name, Input<string> id, DbCredentialState? state = null, CustomResourceOptions? options = null)
        {
            return new DbCredential(name, id, state, options);
        }
    }

    public sealed class DbCredentialArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The description you assign to the DB credentials during creation.
        /// </summary>
        [Input("description", required: true)]
        public Input<string> Description { get; set; } = null!;

        /// <summary>
        /// The password for the DB credentials during creation.
        /// </summary>
        [Input("password", required: true)]
        public Input<string> Password { get; set; } = null!;

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId", required: true)]
        public Input<string> UserId { get; set; } = null!;

        public DbCredentialArgs()
        {
        }
    }

    public sealed class DbCredentialState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// The description you assign to the DB credentials during creation.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The detailed status of INACTIVE lifecycleState.
        /// </summary>
        [Input("lifecycleDetails")]
        public Input<string>? LifecycleDetails { get; set; }

        /// <summary>
        /// The password for the DB credentials during creation.
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        /// <summary>
        /// The credential's current state. After creating a DB credential, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// Date and time the `DbCredential` object was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// Date and time when this credential will expire, in the format defined by RFC3339. Null if it never expires.  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeExpires")]
        public Input<string>? TimeExpires { get; set; }

        /// <summary>
        /// The OCID of the user.
        /// </summary>
        [Input("userId")]
        public Input<string>? UserId { get; set; }

        public DbCredentialState()
        {
        }
    }
}
