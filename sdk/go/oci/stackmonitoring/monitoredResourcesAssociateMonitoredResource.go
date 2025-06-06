// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Monitored Resources Associate Monitored Resource resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// Create an association between two monitored resources. Associations can be created
// between resources from different compartments as long they are in same tenancy.
// User should have required access in both the compartments.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/stackmonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := stackmonitoring.NewMonitoredResourcesAssociateMonitoredResource(ctx, "test_monitored_resources_associate_monitored_resource", &stackmonitoring.MonitoredResourcesAssociateMonitoredResourceArgs{
//				AssociationType:       pulumi.Any(monitoredResourcesAssociateMonitoredResourceAssociationType),
//				CompartmentId:         pulumi.Any(compartmentId),
//				DestinationResourceId: pulumi.Any(testDestinationResource.Id),
//				SourceResourceId:      pulumi.Any(testSourceResource.Id),
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
// MonitoredResourcesAssociateMonitoredResources can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:StackMonitoring/monitoredResourcesAssociateMonitoredResource:MonitoredResourcesAssociateMonitoredResource test_monitored_resources_associate_monitored_resource "id"
// ```
type MonitoredResourcesAssociateMonitoredResource struct {
	pulumi.CustomResourceState

	// Association type to be created between source and destination resources.
	AssociationType pulumi.StringOutput `pulumi:"associationType"`
	// Association category. Possible values are:
	// * System created (SYSTEM),
	// * User created using API (USER_API)
	// * User created using tags (USER_TAG_ASSOC).
	Category pulumi.StringOutput `pulumi:"category"`
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Association Resource Details.
	DestinationResourceDetails MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetailArrayOutput `pulumi:"destinationResourceDetails"`
	// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DestinationResourceId pulumi.StringOutput `pulumi:"destinationResourceId"`
	// Association Resource Details.
	SourceResourceDetails MonitoredResourcesAssociateMonitoredResourceSourceResourceDetailArrayOutput `pulumi:"sourceResourceDetails"`
	// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceResourceId pulumi.StringOutput `pulumi:"sourceResourceId"`
	// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	TenantId pulumi.StringOutput `pulumi:"tenantId"`
	// The time when the association was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewMonitoredResourcesAssociateMonitoredResource registers a new resource with the given unique name, arguments, and options.
func NewMonitoredResourcesAssociateMonitoredResource(ctx *pulumi.Context,
	name string, args *MonitoredResourcesAssociateMonitoredResourceArgs, opts ...pulumi.ResourceOption) (*MonitoredResourcesAssociateMonitoredResource, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AssociationType == nil {
		return nil, errors.New("invalid value for required argument 'AssociationType'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DestinationResourceId == nil {
		return nil, errors.New("invalid value for required argument 'DestinationResourceId'")
	}
	if args.SourceResourceId == nil {
		return nil, errors.New("invalid value for required argument 'SourceResourceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MonitoredResourcesAssociateMonitoredResource
	err := ctx.RegisterResource("oci:StackMonitoring/monitoredResourcesAssociateMonitoredResource:MonitoredResourcesAssociateMonitoredResource", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMonitoredResourcesAssociateMonitoredResource gets an existing MonitoredResourcesAssociateMonitoredResource resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMonitoredResourcesAssociateMonitoredResource(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MonitoredResourcesAssociateMonitoredResourceState, opts ...pulumi.ResourceOption) (*MonitoredResourcesAssociateMonitoredResource, error) {
	var resource MonitoredResourcesAssociateMonitoredResource
	err := ctx.ReadResource("oci:StackMonitoring/monitoredResourcesAssociateMonitoredResource:MonitoredResourcesAssociateMonitoredResource", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MonitoredResourcesAssociateMonitoredResource resources.
type monitoredResourcesAssociateMonitoredResourceState struct {
	// Association type to be created between source and destination resources.
	AssociationType *string `pulumi:"associationType"`
	// Association category. Possible values are:
	// * System created (SYSTEM),
	// * User created using API (USER_API)
	// * User created using tags (USER_TAG_ASSOC).
	Category *string `pulumi:"category"`
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string `pulumi:"compartmentId"`
	// Association Resource Details.
	DestinationResourceDetails []MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetail `pulumi:"destinationResourceDetails"`
	// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DestinationResourceId *string `pulumi:"destinationResourceId"`
	// Association Resource Details.
	SourceResourceDetails []MonitoredResourcesAssociateMonitoredResourceSourceResourceDetail `pulumi:"sourceResourceDetails"`
	// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceResourceId *string `pulumi:"sourceResourceId"`
	// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	TenantId *string `pulumi:"tenantId"`
	// The time when the association was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
}

type MonitoredResourcesAssociateMonitoredResourceState struct {
	// Association type to be created between source and destination resources.
	AssociationType pulumi.StringPtrInput
	// Association category. Possible values are:
	// * System created (SYSTEM),
	// * User created using API (USER_API)
	// * User created using tags (USER_TAG_ASSOC).
	Category pulumi.StringPtrInput
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput
	// Association Resource Details.
	DestinationResourceDetails MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetailArrayInput
	// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DestinationResourceId pulumi.StringPtrInput
	// Association Resource Details.
	SourceResourceDetails MonitoredResourcesAssociateMonitoredResourceSourceResourceDetailArrayInput
	// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceResourceId pulumi.StringPtrInput
	// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	TenantId pulumi.StringPtrInput
	// The time when the association was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
}

func (MonitoredResourcesAssociateMonitoredResourceState) ElementType() reflect.Type {
	return reflect.TypeOf((*monitoredResourcesAssociateMonitoredResourceState)(nil)).Elem()
}

type monitoredResourcesAssociateMonitoredResourceArgs struct {
	// Association type to be created between source and destination resources.
	AssociationType string `pulumi:"associationType"`
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DestinationResourceId string `pulumi:"destinationResourceId"`
	// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceResourceId string `pulumi:"sourceResourceId"`
}

// The set of arguments for constructing a MonitoredResourcesAssociateMonitoredResource resource.
type MonitoredResourcesAssociateMonitoredResourceArgs struct {
	// Association type to be created between source and destination resources.
	AssociationType pulumi.StringInput
	// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput
	// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DestinationResourceId pulumi.StringInput
	// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SourceResourceId pulumi.StringInput
}

func (MonitoredResourcesAssociateMonitoredResourceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*monitoredResourcesAssociateMonitoredResourceArgs)(nil)).Elem()
}

type MonitoredResourcesAssociateMonitoredResourceInput interface {
	pulumi.Input

	ToMonitoredResourcesAssociateMonitoredResourceOutput() MonitoredResourcesAssociateMonitoredResourceOutput
	ToMonitoredResourcesAssociateMonitoredResourceOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceOutput
}

func (*MonitoredResourcesAssociateMonitoredResource) ElementType() reflect.Type {
	return reflect.TypeOf((**MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (i *MonitoredResourcesAssociateMonitoredResource) ToMonitoredResourcesAssociateMonitoredResourceOutput() MonitoredResourcesAssociateMonitoredResourceOutput {
	return i.ToMonitoredResourcesAssociateMonitoredResourceOutputWithContext(context.Background())
}

func (i *MonitoredResourcesAssociateMonitoredResource) ToMonitoredResourcesAssociateMonitoredResourceOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitoredResourcesAssociateMonitoredResourceOutput)
}

// MonitoredResourcesAssociateMonitoredResourceArrayInput is an input type that accepts MonitoredResourcesAssociateMonitoredResourceArray and MonitoredResourcesAssociateMonitoredResourceArrayOutput values.
// You can construct a concrete instance of `MonitoredResourcesAssociateMonitoredResourceArrayInput` via:
//
//	MonitoredResourcesAssociateMonitoredResourceArray{ MonitoredResourcesAssociateMonitoredResourceArgs{...} }
type MonitoredResourcesAssociateMonitoredResourceArrayInput interface {
	pulumi.Input

	ToMonitoredResourcesAssociateMonitoredResourceArrayOutput() MonitoredResourcesAssociateMonitoredResourceArrayOutput
	ToMonitoredResourcesAssociateMonitoredResourceArrayOutputWithContext(context.Context) MonitoredResourcesAssociateMonitoredResourceArrayOutput
}

type MonitoredResourcesAssociateMonitoredResourceArray []MonitoredResourcesAssociateMonitoredResourceInput

func (MonitoredResourcesAssociateMonitoredResourceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (i MonitoredResourcesAssociateMonitoredResourceArray) ToMonitoredResourcesAssociateMonitoredResourceArrayOutput() MonitoredResourcesAssociateMonitoredResourceArrayOutput {
	return i.ToMonitoredResourcesAssociateMonitoredResourceArrayOutputWithContext(context.Background())
}

func (i MonitoredResourcesAssociateMonitoredResourceArray) ToMonitoredResourcesAssociateMonitoredResourceArrayOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitoredResourcesAssociateMonitoredResourceArrayOutput)
}

// MonitoredResourcesAssociateMonitoredResourceMapInput is an input type that accepts MonitoredResourcesAssociateMonitoredResourceMap and MonitoredResourcesAssociateMonitoredResourceMapOutput values.
// You can construct a concrete instance of `MonitoredResourcesAssociateMonitoredResourceMapInput` via:
//
//	MonitoredResourcesAssociateMonitoredResourceMap{ "key": MonitoredResourcesAssociateMonitoredResourceArgs{...} }
type MonitoredResourcesAssociateMonitoredResourceMapInput interface {
	pulumi.Input

	ToMonitoredResourcesAssociateMonitoredResourceMapOutput() MonitoredResourcesAssociateMonitoredResourceMapOutput
	ToMonitoredResourcesAssociateMonitoredResourceMapOutputWithContext(context.Context) MonitoredResourcesAssociateMonitoredResourceMapOutput
}

type MonitoredResourcesAssociateMonitoredResourceMap map[string]MonitoredResourcesAssociateMonitoredResourceInput

func (MonitoredResourcesAssociateMonitoredResourceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (i MonitoredResourcesAssociateMonitoredResourceMap) ToMonitoredResourcesAssociateMonitoredResourceMapOutput() MonitoredResourcesAssociateMonitoredResourceMapOutput {
	return i.ToMonitoredResourcesAssociateMonitoredResourceMapOutputWithContext(context.Background())
}

func (i MonitoredResourcesAssociateMonitoredResourceMap) ToMonitoredResourcesAssociateMonitoredResourceMapOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MonitoredResourcesAssociateMonitoredResourceMapOutput)
}

type MonitoredResourcesAssociateMonitoredResourceOutput struct{ *pulumi.OutputState }

func (MonitoredResourcesAssociateMonitoredResourceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (o MonitoredResourcesAssociateMonitoredResourceOutput) ToMonitoredResourcesAssociateMonitoredResourceOutput() MonitoredResourcesAssociateMonitoredResourceOutput {
	return o
}

func (o MonitoredResourcesAssociateMonitoredResourceOutput) ToMonitoredResourcesAssociateMonitoredResourceOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceOutput {
	return o
}

// Association type to be created between source and destination resources.
func (o MonitoredResourcesAssociateMonitoredResourceOutput) AssociationType() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.AssociationType }).(pulumi.StringOutput)
}

// Association category. Possible values are:
// * System created (SYSTEM),
// * User created using API (USER_API)
// * User created using tags (USER_TAG_ASSOC).
func (o MonitoredResourcesAssociateMonitoredResourceOutput) Category() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.Category }).(pulumi.StringOutput)
}

// Compartment Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o MonitoredResourcesAssociateMonitoredResourceOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Association Resource Details.
func (o MonitoredResourcesAssociateMonitoredResourceOutput) DestinationResourceDetails() MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetailArrayOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetailArrayOutput {
		return v.DestinationResourceDetails
	}).(MonitoredResourcesAssociateMonitoredResourceDestinationResourceDetailArrayOutput)
}

// Destination Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o MonitoredResourcesAssociateMonitoredResourceOutput) DestinationResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput {
		return v.DestinationResourceId
	}).(pulumi.StringOutput)
}

// Association Resource Details.
func (o MonitoredResourcesAssociateMonitoredResourceOutput) SourceResourceDetails() MonitoredResourcesAssociateMonitoredResourceSourceResourceDetailArrayOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) MonitoredResourcesAssociateMonitoredResourceSourceResourceDetailArrayOutput {
		return v.SourceResourceDetails
	}).(MonitoredResourcesAssociateMonitoredResourceSourceResourceDetailArrayOutput)
}

// Source Monitored Resource Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o MonitoredResourcesAssociateMonitoredResourceOutput) SourceResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.SourceResourceId }).(pulumi.StringOutput)
}

// Tenancy Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o MonitoredResourcesAssociateMonitoredResourceOutput) TenantId() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.TenantId }).(pulumi.StringOutput)
}

// The time when the association was created. An RFC3339 formatted datetime string.
func (o MonitoredResourcesAssociateMonitoredResourceOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *MonitoredResourcesAssociateMonitoredResource) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type MonitoredResourcesAssociateMonitoredResourceArrayOutput struct{ *pulumi.OutputState }

func (MonitoredResourcesAssociateMonitoredResourceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (o MonitoredResourcesAssociateMonitoredResourceArrayOutput) ToMonitoredResourcesAssociateMonitoredResourceArrayOutput() MonitoredResourcesAssociateMonitoredResourceArrayOutput {
	return o
}

func (o MonitoredResourcesAssociateMonitoredResourceArrayOutput) ToMonitoredResourcesAssociateMonitoredResourceArrayOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceArrayOutput {
	return o
}

func (o MonitoredResourcesAssociateMonitoredResourceArrayOutput) Index(i pulumi.IntInput) MonitoredResourcesAssociateMonitoredResourceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MonitoredResourcesAssociateMonitoredResource {
		return vs[0].([]*MonitoredResourcesAssociateMonitoredResource)[vs[1].(int)]
	}).(MonitoredResourcesAssociateMonitoredResourceOutput)
}

type MonitoredResourcesAssociateMonitoredResourceMapOutput struct{ *pulumi.OutputState }

func (MonitoredResourcesAssociateMonitoredResourceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MonitoredResourcesAssociateMonitoredResource)(nil)).Elem()
}

func (o MonitoredResourcesAssociateMonitoredResourceMapOutput) ToMonitoredResourcesAssociateMonitoredResourceMapOutput() MonitoredResourcesAssociateMonitoredResourceMapOutput {
	return o
}

func (o MonitoredResourcesAssociateMonitoredResourceMapOutput) ToMonitoredResourcesAssociateMonitoredResourceMapOutputWithContext(ctx context.Context) MonitoredResourcesAssociateMonitoredResourceMapOutput {
	return o
}

func (o MonitoredResourcesAssociateMonitoredResourceMapOutput) MapIndex(k pulumi.StringInput) MonitoredResourcesAssociateMonitoredResourceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MonitoredResourcesAssociateMonitoredResource {
		return vs[0].(map[string]*MonitoredResourcesAssociateMonitoredResource)[vs[1].(string)]
	}).(MonitoredResourcesAssociateMonitoredResourceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MonitoredResourcesAssociateMonitoredResourceInput)(nil)).Elem(), &MonitoredResourcesAssociateMonitoredResource{})
	pulumi.RegisterInputType(reflect.TypeOf((*MonitoredResourcesAssociateMonitoredResourceArrayInput)(nil)).Elem(), MonitoredResourcesAssociateMonitoredResourceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MonitoredResourcesAssociateMonitoredResourceMapInput)(nil)).Elem(), MonitoredResourcesAssociateMonitoredResourceMap{})
	pulumi.RegisterOutputType(MonitoredResourcesAssociateMonitoredResourceOutput{})
	pulumi.RegisterOutputType(MonitoredResourcesAssociateMonitoredResourceArrayOutput{})
	pulumi.RegisterOutputType(MonitoredResourcesAssociateMonitoredResourceMapOutput{})
}
