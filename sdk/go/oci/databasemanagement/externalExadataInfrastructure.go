// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the External Exadata Infrastructure resource in Oracle Cloud Infrastructure Database Management service.
//
// Creates an Oracle Cloud Infrastructure resource for the Exadata infrastructure and enables the Monitoring service for the Exadata infrastructure.
// The following resource/subresources are created:
//
//	Infrastructure
//	Storage server connectors
//	Storage servers
//	Storage grids
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.NewExternalExadataInfrastructure(ctx, "test_external_exadata_infrastructure", &databasemanagement.ExternalExadataInfrastructureArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DbSystemIds:   pulumi.Any(externalExadataInfrastructureDbSystemIds),
//				DisplayName:   pulumi.Any(externalExadataInfrastructureDisplayName),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DiscoveryKey: pulumi.Any(externalExadataInfrastructureDiscoveryKey),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				LicenseModel:       pulumi.Any(externalExadataInfrastructureLicenseModel),
//				StorageServerNames: pulumi.Any(externalExadataInfrastructureStorageServerNames),
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
// ExternalExadataInfrastructures can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure test_external_exadata_infrastructure "id"
// ```
type ExternalExadataInfrastructure struct {
	pulumi.CustomResourceState

	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapOutput `pulumi:"additionalDetails"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
	DatabaseCompartments pulumi.StringArrayOutput `pulumi:"databaseCompartments"`
	// A list of DB systems.
	DatabaseSystems ExternalExadataInfrastructureDatabaseSystemArrayOutput `pulumi:"databaseSystems"`
	// (Updatable) The list of DB systems in the Exadata infrastructure.
	DbSystemIds pulumi.StringArrayOutput `pulumi:"dbSystemIds"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The unique key of the discovery request.
	DiscoveryKey pulumi.StringOutput `pulumi:"discoveryKey"`
	// (Updatable) The name of the Exadata infrastructure.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The internal ID of the Exadata resource.
	InternalId pulumi.StringOutput `pulumi:"internalId"`
	// (Updatable) The Oracle license model that applies to the database management resources.
	LicenseModel pulumi.StringOutput `pulumi:"licenseModel"`
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The rack size of the Exadata infrastructure.
	RackSize pulumi.StringOutput `pulumi:"rackSize"`
	// The current lifecycle state of the database resource.
	State pulumi.StringOutput `pulumi:"state"`
	// The status of the Exadata resource.
	Status pulumi.StringOutput `pulumi:"status"`
	// The Exadata storage server grid of the Exadata infrastructure.
	StorageGrids ExternalExadataInfrastructureStorageGridArrayOutput `pulumi:"storageGrids"`
	// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerNames pulumi.StringArrayOutput `pulumi:"storageServerNames"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The timestamp of the creation of the Exadata resource.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The version of the Exadata resource.
	Version pulumi.StringOutput `pulumi:"version"`
}

// NewExternalExadataInfrastructure registers a new resource with the given unique name, arguments, and options.
func NewExternalExadataInfrastructure(ctx *pulumi.Context,
	name string, args *ExternalExadataInfrastructureArgs, opts ...pulumi.ResourceOption) (*ExternalExadataInfrastructure, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DbSystemIds == nil {
		return nil, errors.New("invalid value for required argument 'DbSystemIds'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExternalExadataInfrastructure
	err := ctx.RegisterResource("oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExternalExadataInfrastructure gets an existing ExternalExadataInfrastructure resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExternalExadataInfrastructure(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExternalExadataInfrastructureState, opts ...pulumi.ResourceOption) (*ExternalExadataInfrastructure, error) {
	var resource ExternalExadataInfrastructure
	err := ctx.ReadResource("oci:DatabaseManagement/externalExadataInfrastructure:ExternalExadataInfrastructure", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExternalExadataInfrastructure resources.
type externalExadataInfrastructureState struct {
	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails map[string]string `pulumi:"additionalDetails"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
	DatabaseCompartments []string `pulumi:"databaseCompartments"`
	// A list of DB systems.
	DatabaseSystems []ExternalExadataInfrastructureDatabaseSystem `pulumi:"databaseSystems"`
	// (Updatable) The list of DB systems in the Exadata infrastructure.
	DbSystemIds []string `pulumi:"dbSystemIds"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The unique key of the discovery request.
	DiscoveryKey *string `pulumi:"discoveryKey"`
	// (Updatable) The name of the Exadata infrastructure.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The internal ID of the Exadata resource.
	InternalId *string `pulumi:"internalId"`
	// (Updatable) The Oracle license model that applies to the database management resources.
	LicenseModel *string `pulumi:"licenseModel"`
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The rack size of the Exadata infrastructure.
	RackSize *string `pulumi:"rackSize"`
	// The current lifecycle state of the database resource.
	State *string `pulumi:"state"`
	// The status of the Exadata resource.
	Status *string `pulumi:"status"`
	// The Exadata storage server grid of the Exadata infrastructure.
	StorageGrids []ExternalExadataInfrastructureStorageGrid `pulumi:"storageGrids"`
	// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerNames []string `pulumi:"storageServerNames"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The timestamp of the creation of the Exadata resource.
	TimeCreated *string `pulumi:"timeCreated"`
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The version of the Exadata resource.
	Version *string `pulumi:"version"`
}

type ExternalExadataInfrastructureState struct {
	// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
	AdditionalDetails pulumi.StringMapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
	DatabaseCompartments pulumi.StringArrayInput
	// A list of DB systems.
	DatabaseSystems ExternalExadataInfrastructureDatabaseSystemArrayInput
	// (Updatable) The list of DB systems in the Exadata infrastructure.
	DbSystemIds pulumi.StringArrayInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The unique key of the discovery request.
	DiscoveryKey pulumi.StringPtrInput
	// (Updatable) The name of the Exadata infrastructure.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The internal ID of the Exadata resource.
	InternalId pulumi.StringPtrInput
	// (Updatable) The Oracle license model that applies to the database management resources.
	LicenseModel pulumi.StringPtrInput
	// The details of the lifecycle state of the Exadata resource.
	LifecycleDetails pulumi.StringPtrInput
	// The rack size of the Exadata infrastructure.
	RackSize pulumi.StringPtrInput
	// The current lifecycle state of the database resource.
	State pulumi.StringPtrInput
	// The status of the Exadata resource.
	Status pulumi.StringPtrInput
	// The Exadata storage server grid of the Exadata infrastructure.
	StorageGrids ExternalExadataInfrastructureStorageGridArrayInput
	// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerNames pulumi.StringArrayInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The timestamp of the creation of the Exadata resource.
	TimeCreated pulumi.StringPtrInput
	// The timestamp of the last update of the Exadata resource.
	TimeUpdated pulumi.StringPtrInput
	// The version of the Exadata resource.
	Version pulumi.StringPtrInput
}

func (ExternalExadataInfrastructureState) ElementType() reflect.Type {
	return reflect.TypeOf((*externalExadataInfrastructureState)(nil)).Elem()
}

type externalExadataInfrastructureArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The list of DB systems in the Exadata infrastructure.
	DbSystemIds []string `pulumi:"dbSystemIds"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The unique key of the discovery request.
	DiscoveryKey *string `pulumi:"discoveryKey"`
	// (Updatable) The name of the Exadata infrastructure.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The Oracle license model that applies to the database management resources.
	LicenseModel *string `pulumi:"licenseModel"`
	// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerNames []string `pulumi:"storageServerNames"`
}

// The set of arguments for constructing a ExternalExadataInfrastructure resource.
type ExternalExadataInfrastructureArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) The list of DB systems in the Exadata infrastructure.
	DbSystemIds pulumi.StringArrayInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The unique key of the discovery request.
	DiscoveryKey pulumi.StringPtrInput
	// (Updatable) The name of the Exadata infrastructure.
	DisplayName pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The Oracle license model that applies to the database management resources.
	LicenseModel pulumi.StringPtrInput
	// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageServerNames pulumi.StringArrayInput
}

func (ExternalExadataInfrastructureArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*externalExadataInfrastructureArgs)(nil)).Elem()
}

type ExternalExadataInfrastructureInput interface {
	pulumi.Input

	ToExternalExadataInfrastructureOutput() ExternalExadataInfrastructureOutput
	ToExternalExadataInfrastructureOutputWithContext(ctx context.Context) ExternalExadataInfrastructureOutput
}

func (*ExternalExadataInfrastructure) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalExadataInfrastructure)(nil)).Elem()
}

func (i *ExternalExadataInfrastructure) ToExternalExadataInfrastructureOutput() ExternalExadataInfrastructureOutput {
	return i.ToExternalExadataInfrastructureOutputWithContext(context.Background())
}

func (i *ExternalExadataInfrastructure) ToExternalExadataInfrastructureOutputWithContext(ctx context.Context) ExternalExadataInfrastructureOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataInfrastructureOutput)
}

// ExternalExadataInfrastructureArrayInput is an input type that accepts ExternalExadataInfrastructureArray and ExternalExadataInfrastructureArrayOutput values.
// You can construct a concrete instance of `ExternalExadataInfrastructureArrayInput` via:
//
//	ExternalExadataInfrastructureArray{ ExternalExadataInfrastructureArgs{...} }
type ExternalExadataInfrastructureArrayInput interface {
	pulumi.Input

	ToExternalExadataInfrastructureArrayOutput() ExternalExadataInfrastructureArrayOutput
	ToExternalExadataInfrastructureArrayOutputWithContext(context.Context) ExternalExadataInfrastructureArrayOutput
}

type ExternalExadataInfrastructureArray []ExternalExadataInfrastructureInput

func (ExternalExadataInfrastructureArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalExadataInfrastructure)(nil)).Elem()
}

func (i ExternalExadataInfrastructureArray) ToExternalExadataInfrastructureArrayOutput() ExternalExadataInfrastructureArrayOutput {
	return i.ToExternalExadataInfrastructureArrayOutputWithContext(context.Background())
}

func (i ExternalExadataInfrastructureArray) ToExternalExadataInfrastructureArrayOutputWithContext(ctx context.Context) ExternalExadataInfrastructureArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataInfrastructureArrayOutput)
}

// ExternalExadataInfrastructureMapInput is an input type that accepts ExternalExadataInfrastructureMap and ExternalExadataInfrastructureMapOutput values.
// You can construct a concrete instance of `ExternalExadataInfrastructureMapInput` via:
//
//	ExternalExadataInfrastructureMap{ "key": ExternalExadataInfrastructureArgs{...} }
type ExternalExadataInfrastructureMapInput interface {
	pulumi.Input

	ToExternalExadataInfrastructureMapOutput() ExternalExadataInfrastructureMapOutput
	ToExternalExadataInfrastructureMapOutputWithContext(context.Context) ExternalExadataInfrastructureMapOutput
}

type ExternalExadataInfrastructureMap map[string]ExternalExadataInfrastructureInput

func (ExternalExadataInfrastructureMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalExadataInfrastructure)(nil)).Elem()
}

func (i ExternalExadataInfrastructureMap) ToExternalExadataInfrastructureMapOutput() ExternalExadataInfrastructureMapOutput {
	return i.ToExternalExadataInfrastructureMapOutputWithContext(context.Background())
}

func (i ExternalExadataInfrastructureMap) ToExternalExadataInfrastructureMapOutputWithContext(ctx context.Context) ExternalExadataInfrastructureMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExternalExadataInfrastructureMapOutput)
}

type ExternalExadataInfrastructureOutput struct{ *pulumi.OutputState }

func (ExternalExadataInfrastructureOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExternalExadataInfrastructure)(nil)).Elem()
}

func (o ExternalExadataInfrastructureOutput) ToExternalExadataInfrastructureOutput() ExternalExadataInfrastructureOutput {
	return o
}

func (o ExternalExadataInfrastructureOutput) ToExternalExadataInfrastructureOutputWithContext(ctx context.Context) ExternalExadataInfrastructureOutput {
	return o
}

// The additional details of the resource defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
func (o ExternalExadataInfrastructureOutput) AdditionalDetails() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringMapOutput { return v.AdditionalDetails }).(pulumi.StringMapOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o ExternalExadataInfrastructureOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of [OCIDs] (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartments.
func (o ExternalExadataInfrastructureOutput) DatabaseCompartments() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringArrayOutput { return v.DatabaseCompartments }).(pulumi.StringArrayOutput)
}

// A list of DB systems.
func (o ExternalExadataInfrastructureOutput) DatabaseSystems() ExternalExadataInfrastructureDatabaseSystemArrayOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) ExternalExadataInfrastructureDatabaseSystemArrayOutput {
		return v.DatabaseSystems
	}).(ExternalExadataInfrastructureDatabaseSystemArrayOutput)
}

// (Updatable) The list of DB systems in the Exadata infrastructure.
func (o ExternalExadataInfrastructureOutput) DbSystemIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringArrayOutput { return v.DbSystemIds }).(pulumi.StringArrayOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ExternalExadataInfrastructureOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The unique key of the discovery request.
func (o ExternalExadataInfrastructureOutput) DiscoveryKey() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.DiscoveryKey }).(pulumi.StringOutput)
}

// (Updatable) The name of the Exadata infrastructure.
func (o ExternalExadataInfrastructureOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ExternalExadataInfrastructureOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The internal ID of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) InternalId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.InternalId }).(pulumi.StringOutput)
}

// (Updatable) The Oracle license model that applies to the database management resources.
func (o ExternalExadataInfrastructureOutput) LicenseModel() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.LicenseModel }).(pulumi.StringOutput)
}

// The details of the lifecycle state of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The rack size of the Exadata infrastructure.
func (o ExternalExadataInfrastructureOutput) RackSize() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.RackSize }).(pulumi.StringOutput)
}

// The current lifecycle state of the database resource.
func (o ExternalExadataInfrastructureOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The status of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// The Exadata storage server grid of the Exadata infrastructure.
func (o ExternalExadataInfrastructureOutput) StorageGrids() ExternalExadataInfrastructureStorageGridArrayOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) ExternalExadataInfrastructureStorageGridArrayOutput {
		return v.StorageGrids
	}).(ExternalExadataInfrastructureStorageGridArrayOutput)
}

// (Updatable) The list of all the Exadata storage server names to be included for monitoring purposes. If not specified, all the Exadata storage servers associated with the DB systems are included.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExternalExadataInfrastructureOutput) StorageServerNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringArrayOutput { return v.StorageServerNames }).(pulumi.StringArrayOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o ExternalExadataInfrastructureOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The timestamp of the creation of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The timestamp of the last update of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The version of the Exadata resource.
func (o ExternalExadataInfrastructureOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v *ExternalExadataInfrastructure) pulumi.StringOutput { return v.Version }).(pulumi.StringOutput)
}

type ExternalExadataInfrastructureArrayOutput struct{ *pulumi.OutputState }

func (ExternalExadataInfrastructureArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExternalExadataInfrastructure)(nil)).Elem()
}

func (o ExternalExadataInfrastructureArrayOutput) ToExternalExadataInfrastructureArrayOutput() ExternalExadataInfrastructureArrayOutput {
	return o
}

func (o ExternalExadataInfrastructureArrayOutput) ToExternalExadataInfrastructureArrayOutputWithContext(ctx context.Context) ExternalExadataInfrastructureArrayOutput {
	return o
}

func (o ExternalExadataInfrastructureArrayOutput) Index(i pulumi.IntInput) ExternalExadataInfrastructureOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExternalExadataInfrastructure {
		return vs[0].([]*ExternalExadataInfrastructure)[vs[1].(int)]
	}).(ExternalExadataInfrastructureOutput)
}

type ExternalExadataInfrastructureMapOutput struct{ *pulumi.OutputState }

func (ExternalExadataInfrastructureMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExternalExadataInfrastructure)(nil)).Elem()
}

func (o ExternalExadataInfrastructureMapOutput) ToExternalExadataInfrastructureMapOutput() ExternalExadataInfrastructureMapOutput {
	return o
}

func (o ExternalExadataInfrastructureMapOutput) ToExternalExadataInfrastructureMapOutputWithContext(ctx context.Context) ExternalExadataInfrastructureMapOutput {
	return o
}

func (o ExternalExadataInfrastructureMapOutput) MapIndex(k pulumi.StringInput) ExternalExadataInfrastructureOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExternalExadataInfrastructure {
		return vs[0].(map[string]*ExternalExadataInfrastructure)[vs[1].(string)]
	}).(ExternalExadataInfrastructureOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataInfrastructureInput)(nil)).Elem(), &ExternalExadataInfrastructure{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataInfrastructureArrayInput)(nil)).Elem(), ExternalExadataInfrastructureArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExternalExadataInfrastructureMapInput)(nil)).Elem(), ExternalExadataInfrastructureMap{})
	pulumi.RegisterOutputType(ExternalExadataInfrastructureOutput{})
	pulumi.RegisterOutputType(ExternalExadataInfrastructureArrayOutput{})
	pulumi.RegisterOutputType(ExternalExadataInfrastructureMapOutput{})
}
