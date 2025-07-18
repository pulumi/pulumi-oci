// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the External Pluggable Database resource in Oracle Cloud Infrastructure Database service.
//
// Registers a new [ExternalPluggableDatabase](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails)
// resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.NewExternalPluggableDatabase(ctx, "test_external_pluggable_database", &database.ExternalPluggableDatabaseArgs{
//				CompartmentId:               pulumi.Any(compartmentId),
//				DisplayName:                 pulumi.Any(externalPluggableDatabaseDisplayName),
//				ExternalContainerDatabaseId: pulumi.Any(testExternalContainerDatabase.Id),
//				DefinedTags:                 pulumi.Any(externalPluggableDatabaseDefinedTags),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				SourceId: pulumi.Any(testSource.Id),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// ExternalPluggableDatabases can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Database/externalPluggableDatabase:ExternalPluggableDatabase test_external_pluggable_database "id"
// ```
type ExternalPluggableDatabase struct {
	pulumi.CustomResourceState

	// The character set of the external database.
	CharacterSet pulumi.StringOutput `pulumi:"characterSet"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The Oracle Database configuration
	DatabaseConfiguration pulumi.StringOutput `pulumi:"databaseConfiguration"`
	// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
	DatabaseEdition pulumi.StringOutput `pulumi:"databaseEdition"`
	// The configuration of the Database Management service.
	DatabaseManagementConfigs ExternalPluggableDatabaseDatabaseManagementConfigArrayOutput `pulumi:"databaseManagementConfigs"`
	// The Oracle Database version.
	DatabaseVersion pulumi.StringOutput `pulumi:"databaseVersion"`
	// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
	DbId pulumi.StringOutput `pulumi:"dbId"`
	// The database packs licensed for the external Oracle Database.
	DbPacks pulumi.StringOutput `pulumi:"dbPacks"`
	// The `DB_UNIQUE_NAME` of the external database.
	DbUniqueName pulumi.StringOutput `pulumi:"dbUniqueName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
	ExternalContainerDatabaseId pulumi.StringOutput `pulumi:"externalContainerDatabaseId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The national character of the external database.
	NcharacterSet pulumi.StringOutput `pulumi:"ncharacterSet"`
	// The configuration of Operations Insights for the external database
	OperationsInsightsConfigs ExternalPluggableDatabaseOperationsInsightsConfigArrayOutput `pulumi:"operationsInsightsConfigs"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceId pulumi.StringOutput `pulumi:"sourceId"`
	// The configuration of Stack Monitoring for the external database.
	StackMonitoringConfigs ExternalPluggableDatabaseStackMonitoringConfigArrayOutput `pulumi:"stackMonitoringConfigs"`
	// The current state of the Oracle Cloud Infrastructure external database resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the database was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
	TimeZone pulumi.StringOutput `pulumi:"timeZone"`
}

// NewExternalPluggableDatabase registers a new resource with the given unique name, arguments, and options.
func NewExternalPluggableDatabase(ctx *pulumi.Context,
	name string, args *ExternalPluggableDatabaseArgs, opts ...pulumi.ResourceOption) (*ExternalPluggableDatabase, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.ExternalContainerDatabaseId == nil {
		return nil, errors.New("invalid value for required argument 'ExternalContainerDatabaseId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalPluggableDatabase
	err := ctx.RegisterResource("oci:Database/externalPluggableDatabase:ExternalPluggableDatabase", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalPluggableDatabase gets an existing ExternalPluggableDatabase resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalPluggableDatabase(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalPluggableDatabaseState, opts ...pulumi.ResourceOption) (*ExternalPluggableDatabase, error) {
	var resource ExternalPluggableDatabase
	err := ctx.ReadResource("oci:Database/externalPluggableDatabase:ExternalPluggableDatabase", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalPluggableDatabase resources.
type externalPluggableDatabaseState struct {
	// The character set of the external database.
	CharacterSet *string `pulumi:"characterSet"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The Oracle Database configuration
	DatabaseConfiguration *string `pulumi:"databaseConfiguration"`
	// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
	DatabaseEdition *string `pulumi:"databaseEdition"`
	// The configuration of the Database Management service.
	DatabaseManagementConfigs []ExternalPluggableDatabaseDatabaseManagementConfig `pulumi:"databaseManagementConfigs"`
	// The Oracle Database version.
	DatabaseVersion *string `pulumi:"databaseVersion"`
	// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
	DbId *string `pulumi:"dbId"`
	// The database packs licensed for the external Oracle Database.
	DbPacks *string `pulumi:"dbPacks"`
	// The `DB_UNIQUE_NAME` of the external database.
	DbUniqueName *string `pulumi:"dbUniqueName"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
	ExternalContainerDatabaseId *string `pulumi:"externalContainerDatabaseId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The national character of the external database.
	NcharacterSet *string `pulumi:"ncharacterSet"`
	// The configuration of Operations Insights for the external database
	OperationsInsightsConfigs []ExternalPluggableDatabaseOperationsInsightsConfig `pulumi:"operationsInsightsConfigs"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceId *string `pulumi:"sourceId"`
	// The configuration of Stack Monitoring for the external database.
	StackMonitoringConfigs []ExternalPluggableDatabaseStackMonitoringConfig `pulumi:"stackMonitoringConfigs"`
	// The current state of the Oracle Cloud Infrastructure external database resource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the database was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
	TimeZone *string `pulumi:"timeZone"`
}

type ExternalPluggableDatabaseState struct {
	// The character set of the external database.
	CharacterSet pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The Oracle Database configuration
	DatabaseConfiguration pulumi.StringPtrInput
	// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
	DatabaseEdition pulumi.StringPtrInput
	// The configuration of the Database Management service.
	DatabaseManagementConfigs ExternalPluggableDatabaseDatabaseManagementConfigArrayInput
	// The Oracle Database version.
	DatabaseVersion pulumi.StringPtrInput
	// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
	DbId pulumi.StringPtrInput
	// The database packs licensed for the external Oracle Database.
	DbPacks pulumi.StringPtrInput
	// The `DB_UNIQUE_NAME` of the external database.
	DbUniqueName pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
	ExternalContainerDatabaseId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The national character of the external database.
	NcharacterSet pulumi.StringPtrInput
	// The configuration of Operations Insights for the external database
	OperationsInsightsConfigs ExternalPluggableDatabaseOperationsInsightsConfigArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceId pulumi.StringPtrInput
	// The configuration of Stack Monitoring for the external database.
	StackMonitoringConfigs ExternalPluggableDatabaseStackMonitoringConfigArrayInput
	// The current state of the Oracle Cloud Infrastructure external database resource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	SystemTags pulumi.StringMapInput
	// The date and time the database was created.
	TimeCreated pulumi.StringPtrInput
	// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
	TimeZone pulumi.StringPtrInput
}

func (ExternalPluggableDatabaseState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalPluggableDatabaseState)(nil)).Elem()
}

type externalPluggableDatabaseArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
	ExternalContainerDatabaseId string `pulumi:"externalContainerDatabaseId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceId *string `pulumi:"sourceId"`
}

// The set of arguments for constructing a ExternalPluggableDatabase resource.
type ExternalPluggableDatabaseArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
	DisplayName pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
	ExternalContainerDatabaseId pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceId pulumi.StringPtrInput
}

func (ExternalPluggableDatabaseArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalPluggableDatabaseArgs)(nil)).Elem()
}

type ExternalPluggableDatabaseInput interface {
	pulumi.Input

	ToExternalPluggableDatabaseOutput() ExternalPluggableDatabaseOutput
	ToExternalPluggableDatabaseOutputWithContext(ctx context.Context) ExternalPluggableDatabaseOutput
}

func (*ExternalPluggableDatabase) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalPluggableDatabase)(nil)).Elem()
}

func (i *ExternalPluggableDatabase) ToExternalPluggableDatabaseOutput() ExternalPluggableDatabaseOutput {
	return i.ToExternalPluggableDatabaseOutputWithContext(context.Background())
}

func (i *ExternalPluggableDatabase) ToExternalPluggableDatabaseOutputWithContext(ctx context.Context) ExternalPluggableDatabaseOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabaseOutput)
}

// ExternalPluggableDatabaseArrayInput is an input type that accepts ExternalPluggableDatabaseArray and ExternalPluggableDatabaseArrayOutput values.
// You can construct a concrete instance of `ExternalPluggableDatabaseArrayInput` via:
//
//	ExternalPluggableDatabaseArray{ ExternalPluggableDatabaseArgs{...} }
type ExternalPluggableDatabaseArrayInput interface {
	pulumi.Input

	ToExternalPluggableDatabaseArrayOutput() ExternalPluggableDatabaseArrayOutput
	ToExternalPluggableDatabaseArrayOutputWithContext(context.Context) ExternalPluggableDatabaseArrayOutput
}

type ExternalPluggableDatabaseArray []ExternalPluggableDatabaseInput

func (ExternalPluggableDatabaseArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalPluggableDatabase)(nil)).Elem()
}

func (i ExternalPluggableDatabaseArray) ToExternalPluggableDatabaseArrayOutput() ExternalPluggableDatabaseArrayOutput {
	return i.ToExternalPluggableDatabaseArrayOutputWithContext(context.Background())
}

func (i ExternalPluggableDatabaseArray) ToExternalPluggableDatabaseArrayOutputWithContext(ctx context.Context) ExternalPluggableDatabaseArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabaseArrayOutput)
}

// ExternalPluggableDatabaseMapInput is an input type that accepts ExternalPluggableDatabaseMap and ExternalPluggableDatabaseMapOutput values.
// You can construct a concrete instance of `ExternalPluggableDatabaseMapInput` via:
//
//	ExternalPluggableDatabaseMap{ "key": ExternalPluggableDatabaseArgs{...} }
type ExternalPluggableDatabaseMapInput interface {
	pulumi.Input

	ToExternalPluggableDatabaseMapOutput() ExternalPluggableDatabaseMapOutput
	ToExternalPluggableDatabaseMapOutputWithContext(context.Context) ExternalPluggableDatabaseMapOutput
}

type ExternalPluggableDatabaseMap map[string]ExternalPluggableDatabaseInput

func (ExternalPluggableDatabaseMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalPluggableDatabase)(nil)).Elem()
}

func (i ExternalPluggableDatabaseMap) ToExternalPluggableDatabaseMapOutput() ExternalPluggableDatabaseMapOutput {
	return i.ToExternalPluggableDatabaseMapOutputWithContext(context.Background())
}

func (i ExternalPluggableDatabaseMap) ToExternalPluggableDatabaseMapOutputWithContext(ctx context.Context) ExternalPluggableDatabaseMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalPluggableDatabaseMapOutput)
}

type ExternalPluggableDatabaseOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabaseOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalPluggableDatabase)(nil)).Elem()
}

func (o ExternalPluggableDatabaseOutput) ToExternalPluggableDatabaseOutput() ExternalPluggableDatabaseOutput {
	return o
}

func (o ExternalPluggableDatabaseOutput) ToExternalPluggableDatabaseOutputWithContext(ctx context.Context) ExternalPluggableDatabaseOutput {
	return o
}

// The character set of the external database.
func (o ExternalPluggableDatabaseOutput) CharacterSet() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.CharacterSet }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o ExternalPluggableDatabaseOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The Oracle Database configuration
func (o ExternalPluggableDatabaseOutput) DatabaseConfiguration() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DatabaseConfiguration }).(pulumi.StringOutput)
}

// The Oracle Database Edition that applies to all the databases on the DB system. Exadata DB systems and 2-node RAC DB systems require ENTERPRISE_EDITION_EXTREME_PERFORMANCE.
func (o ExternalPluggableDatabaseOutput) DatabaseEdition() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DatabaseEdition }).(pulumi.StringOutput)
}

// The configuration of the Database Management service.
func (o ExternalPluggableDatabaseOutput) DatabaseManagementConfigs() ExternalPluggableDatabaseDatabaseManagementConfigArrayOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) ExternalPluggableDatabaseDatabaseManagementConfigArrayOutput {
		return v.DatabaseManagementConfigs
	}).(ExternalPluggableDatabaseDatabaseManagementConfigArrayOutput)
}

// The Oracle Database version.
func (o ExternalPluggableDatabaseOutput) DatabaseVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DatabaseVersion }).(pulumi.StringOutput)
}

// The Oracle Database ID, which identifies an Oracle Database located outside of Oracle Cloud.
func (o ExternalPluggableDatabaseOutput) DbId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DbId }).(pulumi.StringOutput)
}

// The database packs licensed for the external Oracle Database.
func (o ExternalPluggableDatabaseOutput) DbPacks() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DbPacks }).(pulumi.StringOutput)
}

// The `DB_UNIQUE_NAME` of the external database.
func (o ExternalPluggableDatabaseOutput) DbUniqueName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DbUniqueName }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o ExternalPluggableDatabaseOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The user-friendly name for the external database. The name does not have to be unique.
func (o ExternalPluggableDatabaseOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [external container database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalContainerDatabaseDetails) that contains the specified [external pluggable database](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/datatypes/CreateExternalPluggableDatabaseDetails) resource.
func (o ExternalPluggableDatabaseOutput) ExternalContainerDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.ExternalContainerDatabaseId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o ExternalPluggableDatabaseOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Additional information about the current lifecycle state.
func (o ExternalPluggableDatabaseOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The national character of the external database.
func (o ExternalPluggableDatabaseOutput) NcharacterSet() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.NcharacterSet }).(pulumi.StringOutput)
}

// The configuration of Operations Insights for the external database
func (o ExternalPluggableDatabaseOutput) OperationsInsightsConfigs() ExternalPluggableDatabaseOperationsInsightsConfigArrayOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) ExternalPluggableDatabaseOperationsInsightsConfigArrayOutput {
		return v.OperationsInsightsConfigs
	}).(ExternalPluggableDatabaseOperationsInsightsConfigArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the the non-container database that was converted to a pluggable database to create this resource.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalPluggableDatabaseOutput) SourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.SourceId }).(pulumi.StringOutput)
}

// The configuration of Stack Monitoring for the external database.
func (o ExternalPluggableDatabaseOutput) StackMonitoringConfigs() ExternalPluggableDatabaseStackMonitoringConfigArrayOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) ExternalPluggableDatabaseStackMonitoringConfigArrayOutput {
		return v.StackMonitoringConfigs
	}).(ExternalPluggableDatabaseStackMonitoringConfigArrayOutput)
}

// The current state of the Oracle Cloud Infrastructure external database resource.
func (o ExternalPluggableDatabaseOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o ExternalPluggableDatabaseOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the database was created.
func (o ExternalPluggableDatabaseOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time zone of the external database. It is a time zone offset (a character type in the format '[+|-]TZH:TZM') or a time zone region name, depending on how the time zone value was specified when the database was created / last altered.
func (o ExternalPluggableDatabaseOutput) TimeZone() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalPluggableDatabase) pulumi.StringOutput { return v.TimeZone }).(pulumi.StringOutput)
}

type ExternalPluggableDatabaseArrayOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabaseArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalPluggableDatabase)(nil)).Elem()
}

func (o ExternalPluggableDatabaseArrayOutput) ToExternalPluggableDatabaseArrayOutput() ExternalPluggableDatabaseArrayOutput {
	return o
}

func (o ExternalPluggableDatabaseArrayOutput) ToExternalPluggableDatabaseArrayOutputWithContext(ctx context.Context) ExternalPluggableDatabaseArrayOutput {
	return o
}

func (o ExternalPluggableDatabaseArrayOutput) Index(i pulumi.IntInput) ExternalPluggableDatabaseOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalPluggableDatabase {
		return vs[0].([]*ExternalPluggableDatabase)[vs[1].(int)]
	}).(ExternalPluggableDatabaseOutput)
}

type ExternalPluggableDatabaseMapOutput struct{ *pulumi.OutputState }

func (ExternalPluggableDatabaseMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalPluggableDatabase)(nil)).Elem()
}

func (o ExternalPluggableDatabaseMapOutput) ToExternalPluggableDatabaseMapOutput() ExternalPluggableDatabaseMapOutput {
	return o
}

func (o ExternalPluggableDatabaseMapOutput) ToExternalPluggableDatabaseMapOutputWithContext(ctx context.Context) ExternalPluggableDatabaseMapOutput {
	return o
}

func (o ExternalPluggableDatabaseMapOutput) MapIndex(k pulumi.StringInput) ExternalPluggableDatabaseOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalPluggableDatabase {
		return vs[0].(map[string]*ExternalPluggableDatabase)[vs[1].(string)]
	}).(ExternalPluggableDatabaseOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabaseInput)(nil)).Elem(), &ExternalPluggableDatabase{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabaseArrayInput)(nil)).Elem(), ExternalPluggableDatabaseArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalPluggableDatabaseMapInput)(nil)).Elem(), ExternalPluggableDatabaseMap{})
	pulumi.RegisterOutputType(ExternalPluggableDatabaseOutput{})
	pulumi.RegisterOutputType(ExternalPluggableDatabaseArrayOutput{})
	pulumi.RegisterOutputType(ExternalPluggableDatabaseMapOutput{})
}
