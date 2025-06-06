// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasetools

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Database Tools Private Endpoint resource in Oracle Cloud Infrastructure Database Tools service.
//
// Creates a new Database Tools private endpoint.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasetools"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasetools.NewDatabaseToolsPrivateEndpoint(ctx, "test_database_tools_private_endpoint", &databasetools.DatabaseToolsPrivateEndpointArgs{
//				CompartmentId:     pulumi.Any(compartmentId),
//				DisplayName:       pulumi.Any(databaseToolsPrivateEndpointDisplayName),
//				EndpointServiceId: pulumi.Any(testService.Id),
//				SubnetId:          pulumi.Any(testSubnet.Id),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(databaseToolsPrivateEndpointDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Locks: databasetools.DatabaseToolsPrivateEndpointLockArray{
//					&databasetools.DatabaseToolsPrivateEndpointLockArgs{
//						Type:              pulumi.Any(databaseToolsPrivateEndpointLocksType),
//						Message:           pulumi.Any(databaseToolsPrivateEndpointLocksMessage),
//						RelatedResourceId: pulumi.Any(testResource.Id),
//						TimeCreated:       pulumi.Any(databaseToolsPrivateEndpointLocksTimeCreated),
//					},
//				},
//				NsgIds:            pulumi.Any(databaseToolsPrivateEndpointNsgIds),
//				PrivateEndpointIp: pulumi.Any(databaseToolsPrivateEndpointPrivateEndpointIp),
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
// DatabaseToolsPrivateEndpoints can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DatabaseTools/databaseToolsPrivateEndpoint:DatabaseToolsPrivateEndpoint test_database_tools_private_endpoint "id"
// ```
type DatabaseToolsPrivateEndpoint struct {
	pulumi.CustomResourceState

	// A list of additional FQDNs that can be also be used for the private endpoint.
	AdditionalFqdns pulumi.StringArrayOutput `pulumi:"additionalFqdns"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A description of the Database Tools private endpoint.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Then FQDN to use for the private endpoint.
	EndpointFqdn pulumi.StringOutput `pulumi:"endpointFqdn"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
	EndpointServiceId pulumi.StringOutput `pulumi:"endpointServiceId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks DatabaseToolsPrivateEndpointLockArrayOutput `pulumi:"locks"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
	NsgIds pulumi.StringArrayOutput `pulumi:"nsgIds"`
	// The private IP address that represents the access point for the associated endpoint service.
	PrivateEndpointIp pulumi.StringOutput `pulumi:"privateEndpointIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint's VNIC.
	PrivateEndpointVnicId pulumi.StringOutput `pulumi:"privateEndpointVnicId"`
	// Reverse connection configuration details of the private endpoint.
	ReverseConnectionConfigurations DatabaseToolsPrivateEndpointReverseConnectionConfigurationArrayOutput `pulumi:"reverseConnectionConfigurations"`
	// The current state of the Database Tools private endpoint.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewDatabaseToolsPrivateEndpoint registers a new resource with the given unique name, arguments, and options.
func NewDatabaseToolsPrivateEndpoint(ctx *pulumi.Context,
	name string, args *DatabaseToolsPrivateEndpointArgs, opts ...pulumi.ResourceOption) (*DatabaseToolsPrivateEndpoint, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.EndpointServiceId == nil {
		return nil, errors.New("invalid value for required argument 'EndpointServiceId'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DatabaseToolsPrivateEndpoint
	err := ctx.RegisterResource("oci:DatabaseTools/databaseToolsPrivateEndpoint:DatabaseToolsPrivateEndpoint", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDatabaseToolsPrivateEndpoint gets an existing DatabaseToolsPrivateEndpoint resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDatabaseToolsPrivateEndpoint(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DatabaseToolsPrivateEndpointState, opts ...pulumi.ResourceOption) (*DatabaseToolsPrivateEndpoint, error) {
	var resource DatabaseToolsPrivateEndpoint
	err := ctx.ReadResource("oci:DatabaseTools/databaseToolsPrivateEndpoint:DatabaseToolsPrivateEndpoint", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DatabaseToolsPrivateEndpoint resources.
type databaseToolsPrivateEndpointState struct {
	// A list of additional FQDNs that can be also be used for the private endpoint.
	AdditionalFqdns []string `pulumi:"additionalFqdns"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A description of the Database Tools private endpoint.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// Then FQDN to use for the private endpoint.
	EndpointFqdn *string `pulumi:"endpointFqdn"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
	EndpointServiceId *string `pulumi:"endpointServiceId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Locks associated with this resource.
	Locks []DatabaseToolsPrivateEndpointLock `pulumi:"locks"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
	NsgIds []string `pulumi:"nsgIds"`
	// The private IP address that represents the access point for the associated endpoint service.
	PrivateEndpointIp *string `pulumi:"privateEndpointIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint's VNIC.
	PrivateEndpointVnicId *string `pulumi:"privateEndpointVnicId"`
	// Reverse connection configuration details of the private endpoint.
	ReverseConnectionConfigurations []DatabaseToolsPrivateEndpointReverseConnectionConfiguration `pulumi:"reverseConnectionConfigurations"`
	// The current state of the Database Tools private endpoint.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId *string `pulumi:"subnetId"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
	VcnId *string `pulumi:"vcnId"`
}

type DatabaseToolsPrivateEndpointState struct {
	// A list of additional FQDNs that can be also be used for the private endpoint.
	AdditionalFqdns pulumi.StringArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A description of the Database Tools private endpoint.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// Then FQDN to use for the private endpoint.
	EndpointFqdn pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
	EndpointServiceId pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Locks associated with this resource.
	Locks DatabaseToolsPrivateEndpointLockArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
	NsgIds pulumi.StringArrayInput
	// The private IP address that represents the access point for the associated endpoint service.
	PrivateEndpointIp pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint's VNIC.
	PrivateEndpointVnicId pulumi.StringPtrInput
	// Reverse connection configuration details of the private endpoint.
	ReverseConnectionConfigurations DatabaseToolsPrivateEndpointReverseConnectionConfigurationArrayInput
	// The current state of the Database Tools private endpoint.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
	VcnId pulumi.StringPtrInput
}

func (DatabaseToolsPrivateEndpointState) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseToolsPrivateEndpointState)(nil)).Elem()
}

type databaseToolsPrivateEndpointArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A description of the Database Tools private endpoint.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
	EndpointServiceId string `pulumi:"endpointServiceId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Locks associated with this resource.
	Locks []DatabaseToolsPrivateEndpointLock `pulumi:"locks"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
	NsgIds []string `pulumi:"nsgIds"`
	// The private IP address that represents the access point for the associated endpoint service.
	PrivateEndpointIp *string `pulumi:"privateEndpointIp"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a DatabaseToolsPrivateEndpoint resource.
type DatabaseToolsPrivateEndpointArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A description of the Database Tools private endpoint.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
	EndpointServiceId pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// Locks associated with this resource.
	Locks DatabaseToolsPrivateEndpointLockArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
	NsgIds pulumi.StringArrayInput
	// The private IP address that represents the access point for the associated endpoint service.
	PrivateEndpointIp pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SubnetId pulumi.StringInput
}

func (DatabaseToolsPrivateEndpointArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*databaseToolsPrivateEndpointArgs)(nil)).Elem()
}

type DatabaseToolsPrivateEndpointInput interface {
	pulumi.Input

	ToDatabaseToolsPrivateEndpointOutput() DatabaseToolsPrivateEndpointOutput
	ToDatabaseToolsPrivateEndpointOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointOutput
}

func (*DatabaseToolsPrivateEndpoint) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (i *DatabaseToolsPrivateEndpoint) ToDatabaseToolsPrivateEndpointOutput() DatabaseToolsPrivateEndpointOutput {
	return i.ToDatabaseToolsPrivateEndpointOutputWithContext(context.Background())
}

func (i *DatabaseToolsPrivateEndpoint) ToDatabaseToolsPrivateEndpointOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseToolsPrivateEndpointOutput)
}

// DatabaseToolsPrivateEndpointArrayInput is an input type that accepts DatabaseToolsPrivateEndpointArray and DatabaseToolsPrivateEndpointArrayOutput values.
// You can construct a concrete instance of `DatabaseToolsPrivateEndpointArrayInput` via:
//
//	DatabaseToolsPrivateEndpointArray{ DatabaseToolsPrivateEndpointArgs{...} }
type DatabaseToolsPrivateEndpointArrayInput interface {
	pulumi.Input

	ToDatabaseToolsPrivateEndpointArrayOutput() DatabaseToolsPrivateEndpointArrayOutput
	ToDatabaseToolsPrivateEndpointArrayOutputWithContext(context.Context) DatabaseToolsPrivateEndpointArrayOutput
}

type DatabaseToolsPrivateEndpointArray []DatabaseToolsPrivateEndpointInput

func (DatabaseToolsPrivateEndpointArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (i DatabaseToolsPrivateEndpointArray) ToDatabaseToolsPrivateEndpointArrayOutput() DatabaseToolsPrivateEndpointArrayOutput {
	return i.ToDatabaseToolsPrivateEndpointArrayOutputWithContext(context.Background())
}

func (i DatabaseToolsPrivateEndpointArray) ToDatabaseToolsPrivateEndpointArrayOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseToolsPrivateEndpointArrayOutput)
}

// DatabaseToolsPrivateEndpointMapInput is an input type that accepts DatabaseToolsPrivateEndpointMap and DatabaseToolsPrivateEndpointMapOutput values.
// You can construct a concrete instance of `DatabaseToolsPrivateEndpointMapInput` via:
//
//	DatabaseToolsPrivateEndpointMap{ "key": DatabaseToolsPrivateEndpointArgs{...} }
type DatabaseToolsPrivateEndpointMapInput interface {
	pulumi.Input

	ToDatabaseToolsPrivateEndpointMapOutput() DatabaseToolsPrivateEndpointMapOutput
	ToDatabaseToolsPrivateEndpointMapOutputWithContext(context.Context) DatabaseToolsPrivateEndpointMapOutput
}

type DatabaseToolsPrivateEndpointMap map[string]DatabaseToolsPrivateEndpointInput

func (DatabaseToolsPrivateEndpointMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (i DatabaseToolsPrivateEndpointMap) ToDatabaseToolsPrivateEndpointMapOutput() DatabaseToolsPrivateEndpointMapOutput {
	return i.ToDatabaseToolsPrivateEndpointMapOutputWithContext(context.Background())
}

func (i DatabaseToolsPrivateEndpointMap) ToDatabaseToolsPrivateEndpointMapOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DatabaseToolsPrivateEndpointMapOutput)
}

type DatabaseToolsPrivateEndpointOutput struct{ *pulumi.OutputState }

func (DatabaseToolsPrivateEndpointOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (o DatabaseToolsPrivateEndpointOutput) ToDatabaseToolsPrivateEndpointOutput() DatabaseToolsPrivateEndpointOutput {
	return o
}

func (o DatabaseToolsPrivateEndpointOutput) ToDatabaseToolsPrivateEndpointOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointOutput {
	return o
}

// A list of additional FQDNs that can be also be used for the private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) AdditionalFqdns() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringArrayOutput { return v.AdditionalFqdns }).(pulumi.StringArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o DatabaseToolsPrivateEndpointOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A description of the Database Tools private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o DatabaseToolsPrivateEndpointOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// Then FQDN to use for the private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) EndpointFqdn() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.EndpointFqdn }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `DatabaseToolsEndpointService`.
func (o DatabaseToolsPrivateEndpointOutput) EndpointServiceId() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.EndpointServiceId }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o DatabaseToolsPrivateEndpointOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o DatabaseToolsPrivateEndpointOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Locks associated with this resource.
func (o DatabaseToolsPrivateEndpointOutput) Locks() DatabaseToolsPrivateEndpointLockArrayOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) DatabaseToolsPrivateEndpointLockArrayOutput { return v.Locks }).(DatabaseToolsPrivateEndpointLockArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups that the private endpoint's VNIC belongs to.  For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/20160918/NetworkSecurityGroup/).
func (o DatabaseToolsPrivateEndpointOutput) NsgIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringArrayOutput { return v.NsgIds }).(pulumi.StringArrayOutput)
}

// The private IP address that represents the access point for the associated endpoint service.
func (o DatabaseToolsPrivateEndpointOutput) PrivateEndpointIp() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.PrivateEndpointIp }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the private endpoint's VNIC.
func (o DatabaseToolsPrivateEndpointOutput) PrivateEndpointVnicId() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.PrivateEndpointVnicId }).(pulumi.StringOutput)
}

// Reverse connection configuration details of the private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) ReverseConnectionConfigurations() DatabaseToolsPrivateEndpointReverseConnectionConfigurationArrayOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) DatabaseToolsPrivateEndpointReverseConnectionConfigurationArrayOutput {
		return v.ReverseConnectionConfigurations
	}).(DatabaseToolsPrivateEndpointReverseConnectionConfigurationArrayOutput)
}

// The current state of the Database Tools private endpoint.
func (o DatabaseToolsPrivateEndpointOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DatabaseToolsPrivateEndpointOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.SubnetId }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DatabaseToolsPrivateEndpointOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the Database Tools private endpoint was created. An RFC3339 formatted datetime string
func (o DatabaseToolsPrivateEndpointOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the Database Tools private endpoint was updated. An RFC3339 formatted datetime string
func (o DatabaseToolsPrivateEndpointOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN that the private endpoint belongs to.
func (o DatabaseToolsPrivateEndpointOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *DatabaseToolsPrivateEndpoint) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type DatabaseToolsPrivateEndpointArrayOutput struct{ *pulumi.OutputState }

func (DatabaseToolsPrivateEndpointArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (o DatabaseToolsPrivateEndpointArrayOutput) ToDatabaseToolsPrivateEndpointArrayOutput() DatabaseToolsPrivateEndpointArrayOutput {
	return o
}

func (o DatabaseToolsPrivateEndpointArrayOutput) ToDatabaseToolsPrivateEndpointArrayOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointArrayOutput {
	return o
}

func (o DatabaseToolsPrivateEndpointArrayOutput) Index(i pulumi.IntInput) DatabaseToolsPrivateEndpointOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DatabaseToolsPrivateEndpoint {
		return vs[0].([]*DatabaseToolsPrivateEndpoint)[vs[1].(int)]
	}).(DatabaseToolsPrivateEndpointOutput)
}

type DatabaseToolsPrivateEndpointMapOutput struct{ *pulumi.OutputState }

func (DatabaseToolsPrivateEndpointMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DatabaseToolsPrivateEndpoint)(nil)).Elem()
}

func (o DatabaseToolsPrivateEndpointMapOutput) ToDatabaseToolsPrivateEndpointMapOutput() DatabaseToolsPrivateEndpointMapOutput {
	return o
}

func (o DatabaseToolsPrivateEndpointMapOutput) ToDatabaseToolsPrivateEndpointMapOutputWithContext(ctx context.Context) DatabaseToolsPrivateEndpointMapOutput {
	return o
}

func (o DatabaseToolsPrivateEndpointMapOutput) MapIndex(k pulumi.StringInput) DatabaseToolsPrivateEndpointOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DatabaseToolsPrivateEndpoint {
		return vs[0].(map[string]*DatabaseToolsPrivateEndpoint)[vs[1].(string)]
	}).(DatabaseToolsPrivateEndpointOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DatabaseToolsPrivateEndpointInput)(nil)).Elem(), &DatabaseToolsPrivateEndpoint{})
	pulumi.RegisterInputType(reflect.TypeOf((*DatabaseToolsPrivateEndpointArrayInput)(nil)).Elem(), DatabaseToolsPrivateEndpointArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DatabaseToolsPrivateEndpointMapInput)(nil)).Elem(), DatabaseToolsPrivateEndpointMap{})
	pulumi.RegisterOutputType(DatabaseToolsPrivateEndpointOutput{})
	pulumi.RegisterOutputType(DatabaseToolsPrivateEndpointArrayOutput{})
	pulumi.RegisterOutputType(DatabaseToolsPrivateEndpointMapOutput{})
}
