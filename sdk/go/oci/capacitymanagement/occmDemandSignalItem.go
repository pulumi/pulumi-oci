// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Occm Demand Signal Item resource in Oracle Cloud Infrastructure Capacity Management service.
//
// This API will create a demand signal item representing a resource request. This needs to be grouped under a demand signal.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.NewOccmDemandSignalItem(ctx, "test_occm_demand_signal_item", &capacitymanagement.OccmDemandSignalItemArgs{
//				CompartmentId:                 pulumi.Any(compartmentId),
//				DemandQuantity:                pulumi.Any(occmDemandSignalItemDemandQuantity),
//				DemandSignalCatalogResourceId: pulumi.Any(testResource.Id),
//				DemandSignalId:                pulumi.Any(testDemandSignal.Id),
//				Region:                        pulumi.Any(occmDemandSignalItemRegion),
//				RequestType:                   pulumi.Any(occmDemandSignalItemRequestType),
//				ResourceProperties:            pulumi.Any(occmDemandSignalItemResourceProperties),
//				TimeNeededBefore:              pulumi.Any(occmDemandSignalItemTimeNeededBefore),
//				AvailabilityDomain:            pulumi.Any(occmDemandSignalItemAvailabilityDomain),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Notes:               pulumi.Any(occmDemandSignalItemNotes),
//				TargetCompartmentId: pulumi.Any(testCompartment.Id),
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
// OccmDemandSignalItems can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem test_occm_demand_signal_item "id"
// ```
type OccmDemandSignalItem struct {
	pulumi.CustomResourceState

	// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The OCID of the tenancy from which the demand signal item was created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) The quantity of the resource that you want to demand from OCI.
	DemandQuantity pulumi.StringOutput `pulumi:"demandQuantity"`
	// The OCID of the correponding demand signal catalog resource.
	DemandSignalCatalogResourceId pulumi.StringOutput `pulumi:"demandSignalCatalogResourceId"`
	// The OCID of the demand signal under which we need to create this item.
	DemandSignalId pulumi.StringOutput `pulumi:"demandSignalId"`
	// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
	DemandSignalNamespace pulumi.StringOutput `pulumi:"demandSignalNamespace"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
	//
	// NOTE: The previous value gets overwritten with the new one for this once updated.
	Notes pulumi.StringOutput `pulumi:"notes"`
	// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
	Region pulumi.StringOutput `pulumi:"region"`
	// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
	RequestType pulumi.StringOutput `pulumi:"requestType"`
	// The name of the Oracle Cloud Infrastructure resource that you want to request.
	ResourceName pulumi.StringOutput `pulumi:"resourceName"`
	// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
	ResourceProperties pulumi.StringMapOutput `pulumi:"resourceProperties"`
	// The current lifecycle state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
	TargetCompartmentId pulumi.StringOutput `pulumi:"targetCompartmentId"`
	// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeNeededBefore pulumi.StringOutput `pulumi:"timeNeededBefore"`
}

// NewOccmDemandSignalItem registers a new resource with the given unique name, arguments, and options.
func NewOccmDemandSignalItem(ctx *pulumi.Context,
	name string, args *OccmDemandSignalItemArgs, opts ...pulumi.ResourceOption) (*OccmDemandSignalItem, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DemandQuantity == nil {
		return nil, errors.New("invalid value for required argument 'DemandQuantity'")
	}
	if args.DemandSignalCatalogResourceId == nil {
		return nil, errors.New("invalid value for required argument 'DemandSignalCatalogResourceId'")
	}
	if args.DemandSignalId == nil {
		return nil, errors.New("invalid value for required argument 'DemandSignalId'")
	}
	if args.Region == nil {
		return nil, errors.New("invalid value for required argument 'Region'")
	}
	if args.RequestType == nil {
		return nil, errors.New("invalid value for required argument 'RequestType'")
	}
	if args.ResourceProperties == nil {
		return nil, errors.New("invalid value for required argument 'ResourceProperties'")
	}
	if args.TimeNeededBefore == nil {
		return nil, errors.New("invalid value for required argument 'TimeNeededBefore'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource OccmDemandSignalItem
	err := ctx.RegisterResource("oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOccmDemandSignalItem gets an existing OccmDemandSignalItem resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOccmDemandSignalItem(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OccmDemandSignalItemState, opts ...pulumi.ResourceOption) (*OccmDemandSignalItem, error) {
	var resource OccmDemandSignalItem
	err := ctx.ReadResource("oci:CapacityManagement/occmDemandSignalItem:OccmDemandSignalItem", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OccmDemandSignalItem resources.
type occmDemandSignalItemState struct {
	// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the tenancy from which the demand signal item was created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The quantity of the resource that you want to demand from OCI.
	DemandQuantity *string `pulumi:"demandQuantity"`
	// The OCID of the correponding demand signal catalog resource.
	DemandSignalCatalogResourceId *string `pulumi:"demandSignalCatalogResourceId"`
	// The OCID of the demand signal under which we need to create this item.
	DemandSignalId *string `pulumi:"demandSignalId"`
	// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
	DemandSignalNamespace *string `pulumi:"demandSignalNamespace"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
	//
	// NOTE: The previous value gets overwritten with the new one for this once updated.
	Notes *string `pulumi:"notes"`
	// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
	Region *string `pulumi:"region"`
	// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
	RequestType *string `pulumi:"requestType"`
	// The name of the Oracle Cloud Infrastructure resource that you want to request.
	ResourceName *string `pulumi:"resourceName"`
	// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
	ResourceProperties map[string]string `pulumi:"resourceProperties"`
	// The current lifecycle state of the resource.
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
	TargetCompartmentId *string `pulumi:"targetCompartmentId"`
	// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeNeededBefore *string `pulumi:"timeNeededBefore"`
}

type OccmDemandSignalItemState struct {
	// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
	AvailabilityDomain pulumi.StringPtrInput
	// The OCID of the tenancy from which the demand signal item was created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The quantity of the resource that you want to demand from OCI.
	DemandQuantity pulumi.StringPtrInput
	// The OCID of the correponding demand signal catalog resource.
	DemandSignalCatalogResourceId pulumi.StringPtrInput
	// The OCID of the demand signal under which we need to create this item.
	DemandSignalId pulumi.StringPtrInput
	// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
	DemandSignalNamespace pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
	//
	// NOTE: The previous value gets overwritten with the new one for this once updated.
	Notes pulumi.StringPtrInput
	// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
	Region pulumi.StringPtrInput
	// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
	RequestType pulumi.StringPtrInput
	// The name of the Oracle Cloud Infrastructure resource that you want to request.
	ResourceName pulumi.StringPtrInput
	// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
	ResourceProperties pulumi.StringMapInput
	// The current lifecycle state of the resource.
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
	TargetCompartmentId pulumi.StringPtrInput
	// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeNeededBefore pulumi.StringPtrInput
}

func (OccmDemandSignalItemState) ElementType() reflect.Type {
	return reflect.TypeOf((*occmDemandSignalItemState)(nil)).Elem()
}

type occmDemandSignalItemArgs struct {
	// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The OCID of the tenancy from which the demand signal item was created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The quantity of the resource that you want to demand from OCI.
	DemandQuantity string `pulumi:"demandQuantity"`
	// The OCID of the correponding demand signal catalog resource.
	DemandSignalCatalogResourceId string `pulumi:"demandSignalCatalogResourceId"`
	// The OCID of the demand signal under which we need to create this item.
	DemandSignalId string `pulumi:"demandSignalId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
	//
	// NOTE: The previous value gets overwritten with the new one for this once updated.
	Notes *string `pulumi:"notes"`
	// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
	Region string `pulumi:"region"`
	// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
	RequestType string `pulumi:"requestType"`
	// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
	ResourceProperties map[string]string `pulumi:"resourceProperties"`
	// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
	TargetCompartmentId *string `pulumi:"targetCompartmentId"`
	// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeNeededBefore string `pulumi:"timeNeededBefore"`
}

// The set of arguments for constructing a OccmDemandSignalItem resource.
type OccmDemandSignalItemArgs struct {
	// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
	AvailabilityDomain pulumi.StringPtrInput
	// The OCID of the tenancy from which the demand signal item was created.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) The quantity of the resource that you want to demand from OCI.
	DemandQuantity pulumi.StringInput
	// The OCID of the correponding demand signal catalog resource.
	DemandSignalCatalogResourceId pulumi.StringInput
	// The OCID of the demand signal under which we need to create this item.
	DemandSignalId pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
	//
	// NOTE: The previous value gets overwritten with the new one for this once updated.
	Notes pulumi.StringPtrInput
	// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
	Region pulumi.StringInput
	// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
	RequestType pulumi.StringInput
	// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
	ResourceProperties pulumi.StringMapInput
	// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
	TargetCompartmentId pulumi.StringPtrInput
	// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TimeNeededBefore pulumi.StringInput
}

func (OccmDemandSignalItemArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*occmDemandSignalItemArgs)(nil)).Elem()
}

type OccmDemandSignalItemInput interface {
	pulumi.Input

	ToOccmDemandSignalItemOutput() OccmDemandSignalItemOutput
	ToOccmDemandSignalItemOutputWithContext(ctx context.Context) OccmDemandSignalItemOutput
}

func (*OccmDemandSignalItem) ElementType() reflect.Type {
	return reflect.TypeOf((**OccmDemandSignalItem)(nil)).Elem()
}

func (i *OccmDemandSignalItem) ToOccmDemandSignalItemOutput() OccmDemandSignalItemOutput {
	return i.ToOccmDemandSignalItemOutputWithContext(context.Background())
}

func (i *OccmDemandSignalItem) ToOccmDemandSignalItemOutputWithContext(ctx context.Context) OccmDemandSignalItemOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalItemOutput)
}

// OccmDemandSignalItemArrayInput is an input type that accepts OccmDemandSignalItemArray and OccmDemandSignalItemArrayOutput values.
// You can construct a concrete instance of `OccmDemandSignalItemArrayInput` via:
//
//	OccmDemandSignalItemArray{ OccmDemandSignalItemArgs{...} }
type OccmDemandSignalItemArrayInput interface {
	pulumi.Input

	ToOccmDemandSignalItemArrayOutput() OccmDemandSignalItemArrayOutput
	ToOccmDemandSignalItemArrayOutputWithContext(context.Context) OccmDemandSignalItemArrayOutput
}

type OccmDemandSignalItemArray []OccmDemandSignalItemInput

func (OccmDemandSignalItemArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccmDemandSignalItem)(nil)).Elem()
}

func (i OccmDemandSignalItemArray) ToOccmDemandSignalItemArrayOutput() OccmDemandSignalItemArrayOutput {
	return i.ToOccmDemandSignalItemArrayOutputWithContext(context.Background())
}

func (i OccmDemandSignalItemArray) ToOccmDemandSignalItemArrayOutputWithContext(ctx context.Context) OccmDemandSignalItemArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalItemArrayOutput)
}

// OccmDemandSignalItemMapInput is an input type that accepts OccmDemandSignalItemMap and OccmDemandSignalItemMapOutput values.
// You can construct a concrete instance of `OccmDemandSignalItemMapInput` via:
//
//	OccmDemandSignalItemMap{ "key": OccmDemandSignalItemArgs{...} }
type OccmDemandSignalItemMapInput interface {
	pulumi.Input

	ToOccmDemandSignalItemMapOutput() OccmDemandSignalItemMapOutput
	ToOccmDemandSignalItemMapOutputWithContext(context.Context) OccmDemandSignalItemMapOutput
}

type OccmDemandSignalItemMap map[string]OccmDemandSignalItemInput

func (OccmDemandSignalItemMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccmDemandSignalItem)(nil)).Elem()
}

func (i OccmDemandSignalItemMap) ToOccmDemandSignalItemMapOutput() OccmDemandSignalItemMapOutput {
	return i.ToOccmDemandSignalItemMapOutputWithContext(context.Background())
}

func (i OccmDemandSignalItemMap) ToOccmDemandSignalItemMapOutputWithContext(ctx context.Context) OccmDemandSignalItemMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccmDemandSignalItemMapOutput)
}

type OccmDemandSignalItemOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalItemOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OccmDemandSignalItem)(nil)).Elem()
}

func (o OccmDemandSignalItemOutput) ToOccmDemandSignalItemOutput() OccmDemandSignalItemOutput {
	return o
}

func (o OccmDemandSignalItemOutput) ToOccmDemandSignalItemOutputWithContext(ctx context.Context) OccmDemandSignalItemOutput {
	return o
}

// (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
func (o OccmDemandSignalItemOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The OCID of the tenancy from which the demand signal item was created.
func (o OccmDemandSignalItemOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o OccmDemandSignalItemOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) The quantity of the resource that you want to demand from OCI.
func (o OccmDemandSignalItemOutput) DemandQuantity() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.DemandQuantity }).(pulumi.StringOutput)
}

// The OCID of the correponding demand signal catalog resource.
func (o OccmDemandSignalItemOutput) DemandSignalCatalogResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.DemandSignalCatalogResourceId }).(pulumi.StringOutput)
}

// The OCID of the demand signal under which we need to create this item.
func (o OccmDemandSignalItemOutput) DemandSignalId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.DemandSignalId }).(pulumi.StringOutput)
}

// The name of the Oracle Cloud Infrastructure service in consideration for demand signal submission. For example: COMPUTE, NETWORK, GPU etc.
func (o OccmDemandSignalItemOutput) DemandSignalNamespace() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.DemandSignalNamespace }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o OccmDemandSignalItemOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
//
// NOTE: The previous value gets overwritten with the new one for this once updated.
func (o OccmDemandSignalItemOutput) Notes() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.Notes }).(pulumi.StringOutput)
}

// (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
func (o OccmDemandSignalItemOutput) Region() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.Region }).(pulumi.StringOutput)
}

// The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
func (o OccmDemandSignalItemOutput) RequestType() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.RequestType }).(pulumi.StringOutput)
}

// The name of the Oracle Cloud Infrastructure resource that you want to request.
func (o OccmDemandSignalItemOutput) ResourceName() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.ResourceName }).(pulumi.StringOutput)
}

// (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
func (o OccmDemandSignalItemOutput) ResourceProperties() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringMapOutput { return v.ResourceProperties }).(pulumi.StringMapOutput)
}

// The current lifecycle state of the resource.
func (o OccmDemandSignalItemOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o OccmDemandSignalItemOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
func (o OccmDemandSignalItemOutput) TargetCompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.TargetCompartmentId }).(pulumi.StringOutput)
}

// (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o OccmDemandSignalItemOutput) TimeNeededBefore() pulumi.StringOutput {
	return o.ApplyT(func(v *OccmDemandSignalItem) pulumi.StringOutput { return v.TimeNeededBefore }).(pulumi.StringOutput)
}

type OccmDemandSignalItemArrayOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalItemArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccmDemandSignalItem)(nil)).Elem()
}

func (o OccmDemandSignalItemArrayOutput) ToOccmDemandSignalItemArrayOutput() OccmDemandSignalItemArrayOutput {
	return o
}

func (o OccmDemandSignalItemArrayOutput) ToOccmDemandSignalItemArrayOutputWithContext(ctx context.Context) OccmDemandSignalItemArrayOutput {
	return o
}

func (o OccmDemandSignalItemArrayOutput) Index(i pulumi.IntInput) OccmDemandSignalItemOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OccmDemandSignalItem {
		return vs[0].([]*OccmDemandSignalItem)[vs[1].(int)]
	}).(OccmDemandSignalItemOutput)
}

type OccmDemandSignalItemMapOutput struct{ *pulumi.OutputState }

func (OccmDemandSignalItemMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccmDemandSignalItem)(nil)).Elem()
}

func (o OccmDemandSignalItemMapOutput) ToOccmDemandSignalItemMapOutput() OccmDemandSignalItemMapOutput {
	return o
}

func (o OccmDemandSignalItemMapOutput) ToOccmDemandSignalItemMapOutputWithContext(ctx context.Context) OccmDemandSignalItemMapOutput {
	return o
}

func (o OccmDemandSignalItemMapOutput) MapIndex(k pulumi.StringInput) OccmDemandSignalItemOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OccmDemandSignalItem {
		return vs[0].(map[string]*OccmDemandSignalItem)[vs[1].(string)]
	}).(OccmDemandSignalItemOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalItemInput)(nil)).Elem(), &OccmDemandSignalItem{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalItemArrayInput)(nil)).Elem(), OccmDemandSignalItemArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccmDemandSignalItemMapInput)(nil)).Elem(), OccmDemandSignalItemMap{})
	pulumi.RegisterOutputType(OccmDemandSignalItemOutput{})
	pulumi.RegisterOutputType(OccmDemandSignalItemArrayOutput{})
	pulumi.RegisterOutputType(OccmDemandSignalItemMapOutput{})
}
