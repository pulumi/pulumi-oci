// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Pluggable Databases Remote Clone resource in Oracle Cloud Infrastructure Database service.
//
// Clones a pluggable database (PDB) to a different database from the source PDB. The cloned PDB will be started upon completion of the clone operation. The source PDB must be in the `READ_WRITE` openMode when performing the clone.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Database.NewPluggableDatabasesRemoteClone(ctx, "testPluggableDatabasesRemoteClone", &Database.PluggableDatabasesRemoteCloneArgs{
// 			ClonedPdbName:                  pulumi.Any(_var.Pluggable_databases_remote_clone_cloned_pdb_name),
// 			PluggableDatabaseId:            pulumi.Any(oci_database_pluggable_database.Test_pluggable_database.Id),
// 			SourceContainerDbAdminPassword: pulumi.Any(_var.Pluggable_databases_remote_clone_source_container_db_admin_password),
// 			TargetContainerDatabaseId:      pulumi.Any(oci_database_database.Test_database.Id),
// 			PdbAdminPassword:               pulumi.Any(_var.Pluggable_databases_remote_clone_pdb_admin_password),
// 			ShouldPdbAdminAccountBeLocked:  pulumi.Any(_var.Pluggable_databases_remote_clone_should_pdb_admin_account_be_locked),
// 			TargetTdeWalletPassword:        pulumi.Any(_var.Pluggable_databases_remote_clone_target_tde_wallet_password),
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Import is not supported for this resource.
type PluggableDatabasesRemoteClone struct {
	pulumi.CustomResourceState

	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringOutput `pulumi:"clonedPdbName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings PluggableDatabasesRemoteCloneConnectionStringArrayOutput `pulumi:"connectionStrings"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId pulumi.StringOutput `pulumi:"containerDatabaseId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted pulumi.BoolOutput `pulumi:"isRestricted"`
	// Detailed message for the lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode pulumi.StringOutput `pulumi:"openMode"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringOutput `pulumi:"pdbAdminPassword"`
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName pulumi.StringOutput `pulumi:"pdbName"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringOutput `pulumi:"pluggableDatabaseId"`
	// The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
	ShouldPdbAdminAccountBeLocked pulumi.BoolOutput `pulumi:"shouldPdbAdminAccountBeLocked"`
	// The DB system administrator password of the source CDB.
	SourceContainerDbAdminPassword pulumi.StringOutput `pulumi:"sourceContainerDbAdminPassword"`
	// The current state of the pluggable database.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target CDB
	TargetContainerDatabaseId pulumi.StringOutput `pulumi:"targetContainerDatabaseId"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringOutput `pulumi:"targetTdeWalletPassword"`
	// The date and time the pluggable database was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewPluggableDatabasesRemoteClone registers a new resource with the given unique name, arguments, and options.
func NewPluggableDatabasesRemoteClone(ctx *pulumi.Context,
	name string, args *PluggableDatabasesRemoteCloneArgs, opts ...pulumi.ResourceOption) (*PluggableDatabasesRemoteClone, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ClonedPdbName == nil {
		return nil, errors.New("invalid value for required argument 'ClonedPdbName'")
	}
	if args.PluggableDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'PluggableDatabaseId'")
	}
	if args.SourceContainerDbAdminPassword == nil {
		return nil, errors.New("invalid value for required argument 'SourceContainerDbAdminPassword'")
	}
	if args.TargetContainerDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'TargetContainerDatabaseId'")
	}
	var resource PluggableDatabasesRemoteClone
	err := ctx.RegisterResource("oci:Database/pluggableDatabasesRemoteClone:PluggableDatabasesRemoteClone", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPluggableDatabasesRemoteClone gets an existing PluggableDatabasesRemoteClone resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPluggableDatabasesRemoteClone(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PluggableDatabasesRemoteCloneState, opts ...pulumi.ResourceOption) (*PluggableDatabasesRemoteClone, error) {
	var resource PluggableDatabasesRemoteClone
	err := ctx.ReadResource("oci:Database/pluggableDatabasesRemoteClone:PluggableDatabasesRemoteClone", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PluggableDatabasesRemoteClone resources.
type pluggableDatabasesRemoteCloneState struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName *string `pulumi:"clonedPdbName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings []PluggableDatabasesRemoteCloneConnectionString `pulumi:"connectionStrings"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId *string `pulumi:"containerDatabaseId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted *bool `pulumi:"isRestricted"`
	// Detailed message for the lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode *string `pulumi:"openMode"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword *string `pulumi:"pdbAdminPassword"`
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName *string `pulumi:"pdbName"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId *string `pulumi:"pluggableDatabaseId"`
	// The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
	ShouldPdbAdminAccountBeLocked *bool `pulumi:"shouldPdbAdminAccountBeLocked"`
	// The DB system administrator password of the source CDB.
	SourceContainerDbAdminPassword *string `pulumi:"sourceContainerDbAdminPassword"`
	// The current state of the pluggable database.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target CDB
	TargetContainerDatabaseId *string `pulumi:"targetContainerDatabaseId"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword *string `pulumi:"targetTdeWalletPassword"`
	// The date and time the pluggable database was created.
	TimeCreated *string `pulumi:"timeCreated"`
}

type PluggableDatabasesRemoteCloneState struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// Connection strings to connect to an Oracle Pluggable Database.
	ConnectionStrings PluggableDatabasesRemoteCloneConnectionStringArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
	ContainerDatabaseId pulumi.StringPtrInput
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.MapInput
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
	IsRestricted pulumi.BoolPtrInput
	// Detailed message for the lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
	OpenMode pulumi.StringPtrInput
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringPtrInput
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	PdbName pulumi.StringPtrInput
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringPtrInput
	// The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
	ShouldPdbAdminAccountBeLocked pulumi.BoolPtrInput
	// The DB system administrator password of the source CDB.
	SourceContainerDbAdminPassword pulumi.StringPtrInput
	// The current state of the pluggable database.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target CDB
	TargetContainerDatabaseId pulumi.StringPtrInput
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringPtrInput
	// The date and time the pluggable database was created.
	TimeCreated pulumi.StringPtrInput
}

func (PluggableDatabasesRemoteCloneState) ElementType() reflect.Type {
	return reflect.TypeOf((*pluggableDatabasesRemoteCloneState)(nil)).Elem()
}

type pluggableDatabasesRemoteCloneArgs struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName string `pulumi:"clonedPdbName"`
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword *string `pulumi:"pdbAdminPassword"`
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId string `pulumi:"pluggableDatabaseId"`
	// The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
	ShouldPdbAdminAccountBeLocked *bool `pulumi:"shouldPdbAdminAccountBeLocked"`
	// The DB system administrator password of the source CDB.
	SourceContainerDbAdminPassword string `pulumi:"sourceContainerDbAdminPassword"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target CDB
	TargetContainerDatabaseId string `pulumi:"targetContainerDatabaseId"`
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword *string `pulumi:"targetTdeWalletPassword"`
}

// The set of arguments for constructing a PluggableDatabasesRemoteClone resource.
type PluggableDatabasesRemoteCloneArgs struct {
	// The name for the pluggable database (PDB). The name is unique in the context of a [container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/Database/). The name must begin with an alphabetic character and can contain a maximum of thirty alphanumeric characters. Special characters are not permitted. The pluggable database name should not be same as the container database name.
	ClonedPdbName pulumi.StringInput
	// A strong password for PDB Admin of the newly cloned PDB. The password must be at least nine characters and contain at least two uppercase, two lowercase, two numbers, and two special characters. The special characters must be _, \#, or -.
	PdbAdminPassword pulumi.StringPtrInput
	// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	PluggableDatabaseId pulumi.StringInput
	// The locked mode of the pluggable database admin account. If false, the user needs to provide the PDB Admin Password to connect to it. If true, the pluggable database will be locked and user cannot login to it.
	ShouldPdbAdminAccountBeLocked pulumi.BoolPtrInput
	// The DB system administrator password of the source CDB.
	SourceContainerDbAdminPassword pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target CDB
	TargetContainerDatabaseId pulumi.StringInput
	// The existing TDE wallet password of the target CDB.
	TargetTdeWalletPassword pulumi.StringPtrInput
}

func (PluggableDatabasesRemoteCloneArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*pluggableDatabasesRemoteCloneArgs)(nil)).Elem()
}

type PluggableDatabasesRemoteCloneInput interface {
	pulumi.Input

	ToPluggableDatabasesRemoteCloneOutput() PluggableDatabasesRemoteCloneOutput
	ToPluggableDatabasesRemoteCloneOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneOutput
}

func (*PluggableDatabasesRemoteClone) ElementType() reflect.Type {
	return reflect.TypeOf((**PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (i *PluggableDatabasesRemoteClone) ToPluggableDatabasesRemoteCloneOutput() PluggableDatabasesRemoteCloneOutput {
	return i.ToPluggableDatabasesRemoteCloneOutputWithContext(context.Background())
}

func (i *PluggableDatabasesRemoteClone) ToPluggableDatabasesRemoteCloneOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PluggableDatabasesRemoteCloneOutput)
}

// PluggableDatabasesRemoteCloneArrayInput is an input type that accepts PluggableDatabasesRemoteCloneArray and PluggableDatabasesRemoteCloneArrayOutput values.
// You can construct a concrete instance of `PluggableDatabasesRemoteCloneArrayInput` via:
//
//          PluggableDatabasesRemoteCloneArray{ PluggableDatabasesRemoteCloneArgs{...} }
type PluggableDatabasesRemoteCloneArrayInput interface {
	pulumi.Input

	ToPluggableDatabasesRemoteCloneArrayOutput() PluggableDatabasesRemoteCloneArrayOutput
	ToPluggableDatabasesRemoteCloneArrayOutputWithContext(context.Context) PluggableDatabasesRemoteCloneArrayOutput
}

type PluggableDatabasesRemoteCloneArray []PluggableDatabasesRemoteCloneInput

func (PluggableDatabasesRemoteCloneArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (i PluggableDatabasesRemoteCloneArray) ToPluggableDatabasesRemoteCloneArrayOutput() PluggableDatabasesRemoteCloneArrayOutput {
	return i.ToPluggableDatabasesRemoteCloneArrayOutputWithContext(context.Background())
}

func (i PluggableDatabasesRemoteCloneArray) ToPluggableDatabasesRemoteCloneArrayOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PluggableDatabasesRemoteCloneArrayOutput)
}

// PluggableDatabasesRemoteCloneMapInput is an input type that accepts PluggableDatabasesRemoteCloneMap and PluggableDatabasesRemoteCloneMapOutput values.
// You can construct a concrete instance of `PluggableDatabasesRemoteCloneMapInput` via:
//
//          PluggableDatabasesRemoteCloneMap{ "key": PluggableDatabasesRemoteCloneArgs{...} }
type PluggableDatabasesRemoteCloneMapInput interface {
	pulumi.Input

	ToPluggableDatabasesRemoteCloneMapOutput() PluggableDatabasesRemoteCloneMapOutput
	ToPluggableDatabasesRemoteCloneMapOutputWithContext(context.Context) PluggableDatabasesRemoteCloneMapOutput
}

type PluggableDatabasesRemoteCloneMap map[string]PluggableDatabasesRemoteCloneInput

func (PluggableDatabasesRemoteCloneMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (i PluggableDatabasesRemoteCloneMap) ToPluggableDatabasesRemoteCloneMapOutput() PluggableDatabasesRemoteCloneMapOutput {
	return i.ToPluggableDatabasesRemoteCloneMapOutputWithContext(context.Background())
}

func (i PluggableDatabasesRemoteCloneMap) ToPluggableDatabasesRemoteCloneMapOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PluggableDatabasesRemoteCloneMapOutput)
}

type PluggableDatabasesRemoteCloneOutput struct{ *pulumi.OutputState }

func (PluggableDatabasesRemoteCloneOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (o PluggableDatabasesRemoteCloneOutput) ToPluggableDatabasesRemoteCloneOutput() PluggableDatabasesRemoteCloneOutput {
	return o
}

func (o PluggableDatabasesRemoteCloneOutput) ToPluggableDatabasesRemoteCloneOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneOutput {
	return o
}

type PluggableDatabasesRemoteCloneArrayOutput struct{ *pulumi.OutputState }

func (PluggableDatabasesRemoteCloneArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (o PluggableDatabasesRemoteCloneArrayOutput) ToPluggableDatabasesRemoteCloneArrayOutput() PluggableDatabasesRemoteCloneArrayOutput {
	return o
}

func (o PluggableDatabasesRemoteCloneArrayOutput) ToPluggableDatabasesRemoteCloneArrayOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneArrayOutput {
	return o
}

func (o PluggableDatabasesRemoteCloneArrayOutput) Index(i pulumi.IntInput) PluggableDatabasesRemoteCloneOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *PluggableDatabasesRemoteClone {
		return vs[0].([]*PluggableDatabasesRemoteClone)[vs[1].(int)]
	}).(PluggableDatabasesRemoteCloneOutput)
}

type PluggableDatabasesRemoteCloneMapOutput struct{ *pulumi.OutputState }

func (PluggableDatabasesRemoteCloneMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*PluggableDatabasesRemoteClone)(nil)).Elem()
}

func (o PluggableDatabasesRemoteCloneMapOutput) ToPluggableDatabasesRemoteCloneMapOutput() PluggableDatabasesRemoteCloneMapOutput {
	return o
}

func (o PluggableDatabasesRemoteCloneMapOutput) ToPluggableDatabasesRemoteCloneMapOutputWithContext(ctx context.Context) PluggableDatabasesRemoteCloneMapOutput {
	return o
}

func (o PluggableDatabasesRemoteCloneMapOutput) MapIndex(k pulumi.StringInput) PluggableDatabasesRemoteCloneOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *PluggableDatabasesRemoteClone {
		return vs[0].(map[string]*PluggableDatabasesRemoteClone)[vs[1].(string)]
	}).(PluggableDatabasesRemoteCloneOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*PluggableDatabasesRemoteCloneInput)(nil)).Elem(), &PluggableDatabasesRemoteClone{})
	pulumi.RegisterInputType(reflect.TypeOf((*PluggableDatabasesRemoteCloneArrayInput)(nil)).Elem(), PluggableDatabasesRemoteCloneArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*PluggableDatabasesRemoteCloneMapInput)(nil)).Elem(), PluggableDatabasesRemoteCloneMap{})
	pulumi.RegisterOutputType(PluggableDatabasesRemoteCloneOutput{})
	pulumi.RegisterOutputType(PluggableDatabasesRemoteCloneArrayOutput{})
	pulumi.RegisterOutputType(PluggableDatabasesRemoteCloneMapOutput{})
}
