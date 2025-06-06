// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Vtap resource in Oracle Cloud Infrastructure Core service.
//
// Creates a virtual test access point (VTAP) in the specified compartment.
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the VTAP.
// For more information about compartments and access control, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
// For information about OCIDs, see [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
//
// You may optionally specify a *display name* for the VTAP, otherwise a default is provided.
// It does not have to be unique, and you can change it.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewVtap(ctx, "test_vtap", &core.VtapArgs{
//				CaptureFilterId: pulumi.Any(testCaptureFilter.Id),
//				CompartmentId:   pulumi.Any(compartmentId),
//				SourceId:        pulumi.Any(testSource.Id),
//				VcnId:           pulumi.Any(testVcn.Id),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName:           pulumi.Any(vtapDisplayName),
//				EncapsulationProtocol: pulumi.Any(vtapEncapsulationProtocol),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				IsVtapEnabled:                 pulumi.Any(vtapIsVtapEnabled),
//				MaxPacketSize:                 pulumi.Any(vtapMaxPacketSize),
//				SourcePrivateEndpointIp:       pulumi.Any(vtapSourcePrivateEndpointIp),
//				SourcePrivateEndpointSubnetId: pulumi.Any(testSubnet.Id),
//				SourceType:                    pulumi.Any(vtapSourceType),
//				TargetId:                      pulumi.Any(testTarget.Id),
//				TargetIp:                      pulumi.Any(vtapTargetIp),
//				TargetType:                    pulumi.Any(vtapTargetType),
//				TrafficMode:                   pulumi.Any(vtapTrafficMode),
//				VxlanNetworkIdentifier:        pulumi.Any(vtapVxlanNetworkIdentifier),
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
// Vtaps can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/vtap:Vtap test_vtap "id"
// ```
type Vtap struct {
	pulumi.CustomResourceState

	// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	CaptureFilterId pulumi.StringOutput `pulumi:"captureFilterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol pulumi.StringOutput `pulumi:"encapsulationProtocol"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled pulumi.BoolOutput `pulumi:"isVtapEnabled"`
	// The VTAP's current running state.
	LifecycleStateDetails pulumi.StringOutput `pulumi:"lifecycleStateDetails"`
	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize pulumi.IntOutput `pulumi:"maxPacketSize"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
	SourceId pulumi.StringOutput `pulumi:"sourceId"`
	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIp pulumi.StringOutput `pulumi:"sourcePrivateEndpointIp"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetId pulumi.StringOutput `pulumi:"sourcePrivateEndpointSubnetId"`
	// (Updatable) The source type for the VTAP.
	SourceType pulumi.StringOutput `pulumi:"sourceType"`
	// The VTAP's administrative lifecycle state.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId pulumi.StringOutput `pulumi:"targetId"`
	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIp pulumi.StringOutput `pulumi:"targetIp"`
	// (Updatable) The target type for the VTAP.
	TargetType pulumi.StringOutput `pulumi:"targetType"`
	// The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode pulumi.StringOutput `pulumi:"trafficMode"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VxlanNetworkIdentifier pulumi.StringOutput `pulumi:"vxlanNetworkIdentifier"`
}

// NewVtap registers a new resource with the given unique name, arguments, and options.
func NewVtap(ctx *pulumi.Context,
	name string, args *VtapArgs, opts ...pulumi.ResourceOption) (*Vtap, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CaptureFilterId == nil {
		return nil, errors.New("invalid value for required argument 'CaptureFilterId'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.SourceId == nil {
		return nil, errors.New("invalid value for required argument 'SourceId'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Vtap
	err := ctx.RegisterResource("oci:Core/vtap:Vtap", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVtap gets an existing Vtap resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVtap(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VtapState, opts ...pulumi.ResourceOption) (*Vtap, error) {
	var resource Vtap
	err := ctx.ReadResource("oci:Core/vtap:Vtap", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Vtap resources.
type vtapState struct {
	// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	CaptureFilterId *string `pulumi:"captureFilterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol *string `pulumi:"encapsulationProtocol"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled *bool `pulumi:"isVtapEnabled"`
	// The VTAP's current running state.
	LifecycleStateDetails *string `pulumi:"lifecycleStateDetails"`
	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize *int `pulumi:"maxPacketSize"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
	SourceId *string `pulumi:"sourceId"`
	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIp *string `pulumi:"sourcePrivateEndpointIp"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetId *string `pulumi:"sourcePrivateEndpointSubnetId"`
	// (Updatable) The source type for the VTAP.
	SourceType *string `pulumi:"sourceType"`
	// The VTAP's administrative lifecycle state.
	State *string `pulumi:"state"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId *string `pulumi:"targetId"`
	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIp *string `pulumi:"targetIp"`
	// (Updatable) The target type for the VTAP.
	TargetType *string `pulumi:"targetType"`
	// The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode *string `pulumi:"trafficMode"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId *string `pulumi:"vcnId"`
	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VxlanNetworkIdentifier *string `pulumi:"vxlanNetworkIdentifier"`
}

type VtapState struct {
	// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	CaptureFilterId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled pulumi.BoolPtrInput
	// The VTAP's current running state.
	LifecycleStateDetails pulumi.StringPtrInput
	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize pulumi.IntPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
	SourceId pulumi.StringPtrInput
	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIp pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetId pulumi.StringPtrInput
	// (Updatable) The source type for the VTAP.
	SourceType pulumi.StringPtrInput
	// The VTAP's administrative lifecycle state.
	State pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId pulumi.StringPtrInput
	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIp pulumi.StringPtrInput
	// (Updatable) The target type for the VTAP.
	TargetType pulumi.StringPtrInput
	// The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId pulumi.StringPtrInput
	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VxlanNetworkIdentifier pulumi.StringPtrInput
}

func (VtapState) ElementType() reflect.Type {
	return reflect.TypeOf((*vtapState)(nil)).Elem()
}

type vtapArgs struct {
	// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	CaptureFilterId string `pulumi:"captureFilterId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol *string `pulumi:"encapsulationProtocol"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled *bool `pulumi:"isVtapEnabled"`
	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize *int `pulumi:"maxPacketSize"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
	SourceId string `pulumi:"sourceId"`
	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIp *string `pulumi:"sourcePrivateEndpointIp"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetId *string `pulumi:"sourcePrivateEndpointSubnetId"`
	// (Updatable) The source type for the VTAP.
	SourceType *string `pulumi:"sourceType"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId *string `pulumi:"targetId"`
	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIp *string `pulumi:"targetIp"`
	// (Updatable) The target type for the VTAP.
	TargetType *string `pulumi:"targetType"`
	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode *string `pulumi:"trafficMode"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId string `pulumi:"vcnId"`
	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VxlanNetworkIdentifier *string `pulumi:"vxlanNetworkIdentifier"`
}

// The set of arguments for constructing a Vtap resource.
type VtapArgs struct {
	// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	CaptureFilterId pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
	EncapsulationProtocol pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Used to start or stop a `Vtap` resource.
	// * `TRUE` directs the VTAP to start mirroring traffic.
	// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
	IsVtapEnabled pulumi.BoolPtrInput
	// (Updatable) The maximum size of the packets to be included in the filter.
	MaxPacketSize pulumi.IntPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
	SourceId pulumi.StringInput
	// (Updatable) The IP Address of the source private endpoint.
	SourcePrivateEndpointIp pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
	SourcePrivateEndpointSubnetId pulumi.StringPtrInput
	// (Updatable) The source type for the VTAP.
	SourceType pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
	TargetId pulumi.StringPtrInput
	// (Updatable) The IP address of the destination resource where mirrored packets are sent.
	TargetIp pulumi.StringPtrInput
	// (Updatable) The target type for the VTAP.
	TargetType pulumi.StringPtrInput
	// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
	TrafficMode pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
	VcnId pulumi.StringInput
	// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VxlanNetworkIdentifier pulumi.StringPtrInput
}

func (VtapArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vtapArgs)(nil)).Elem()
}

type VtapInput interface {
	pulumi.Input

	ToVtapOutput() VtapOutput
	ToVtapOutputWithContext(ctx context.Context) VtapOutput
}

func (*Vtap) ElementType() reflect.Type {
	return reflect.TypeOf((**Vtap)(nil)).Elem()
}

func (i *Vtap) ToVtapOutput() VtapOutput {
	return i.ToVtapOutputWithContext(context.Background())
}

func (i *Vtap) ToVtapOutputWithContext(ctx context.Context) VtapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VtapOutput)
}

// VtapArrayInput is an input type that accepts VtapArray and VtapArrayOutput values.
// You can construct a concrete instance of `VtapArrayInput` via:
//
//	VtapArray{ VtapArgs{...} }
type VtapArrayInput interface {
	pulumi.Input

	ToVtapArrayOutput() VtapArrayOutput
	ToVtapArrayOutputWithContext(context.Context) VtapArrayOutput
}

type VtapArray []VtapInput

func (VtapArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Vtap)(nil)).Elem()
}

func (i VtapArray) ToVtapArrayOutput() VtapArrayOutput {
	return i.ToVtapArrayOutputWithContext(context.Background())
}

func (i VtapArray) ToVtapArrayOutputWithContext(ctx context.Context) VtapArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VtapArrayOutput)
}

// VtapMapInput is an input type that accepts VtapMap and VtapMapOutput values.
// You can construct a concrete instance of `VtapMapInput` via:
//
//	VtapMap{ "key": VtapArgs{...} }
type VtapMapInput interface {
	pulumi.Input

	ToVtapMapOutput() VtapMapOutput
	ToVtapMapOutputWithContext(context.Context) VtapMapOutput
}

type VtapMap map[string]VtapInput

func (VtapMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Vtap)(nil)).Elem()
}

func (i VtapMap) ToVtapMapOutput() VtapMapOutput {
	return i.ToVtapMapOutputWithContext(context.Background())
}

func (i VtapMap) ToVtapMapOutputWithContext(ctx context.Context) VtapMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VtapMapOutput)
}

type VtapOutput struct{ *pulumi.OutputState }

func (VtapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Vtap)(nil)).Elem()
}

func (o VtapOutput) ToVtapOutput() VtapOutput {
	return o
}

func (o VtapOutput) ToVtapOutputWithContext(ctx context.Context) VtapOutput {
	return o
}

// (Updatable) The capture filter's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
func (o VtapOutput) CaptureFilterId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.CaptureFilterId }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the `Vtap` resource.
func (o VtapOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o VtapOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o VtapOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Defines an encapsulation header type for the VTAP's mirrored traffic.
func (o VtapOutput) EncapsulationProtocol() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.EncapsulationProtocol }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o VtapOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) Used to start or stop a `Vtap` resource.
// * `TRUE` directs the VTAP to start mirroring traffic.
// * `FALSE` (Default) directs the VTAP to stop mirroring traffic.
func (o VtapOutput) IsVtapEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v *Vtap) pulumi.BoolOutput { return v.IsVtapEnabled }).(pulumi.BoolOutput)
}

// The VTAP's current running state.
func (o VtapOutput) LifecycleStateDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.LifecycleStateDetails }).(pulumi.StringOutput)
}

// (Updatable) The maximum size of the packets to be included in the filter.
func (o VtapOutput) MaxPacketSize() pulumi.IntOutput {
	return o.ApplyT(func(v *Vtap) pulumi.IntOutput { return v.MaxPacketSize }).(pulumi.IntOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source point where packets are captured.
func (o VtapOutput) SourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.SourceId }).(pulumi.StringOutput)
}

// (Updatable) The IP Address of the source private endpoint.
func (o VtapOutput) SourcePrivateEndpointIp() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.SourcePrivateEndpointIp }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that source private endpoint belongs to.
func (o VtapOutput) SourcePrivateEndpointSubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.SourcePrivateEndpointSubnetId }).(pulumi.StringOutput)
}

// (Updatable) The source type for the VTAP.
func (o VtapOutput) SourceType() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.SourceType }).(pulumi.StringOutput)
}

// The VTAP's administrative lifecycle state.
func (o VtapOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the destination resource where mirrored packets are sent.
func (o VtapOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.TargetId }).(pulumi.StringOutput)
}

// (Updatable) The IP address of the destination resource where mirrored packets are sent.
func (o VtapOutput) TargetIp() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.TargetIp }).(pulumi.StringOutput)
}

// (Updatable) The target type for the VTAP.
func (o VtapOutput) TargetType() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.TargetType }).(pulumi.StringOutput)
}

// The date and time the VTAP was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2020-08-25T21:10:29.600Z`
func (o VtapOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) Used to control the priority of traffic. It is an optional field. If it not passed, the value is DEFAULT
func (o VtapOutput) TrafficMode() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.TrafficMode }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN containing the `Vtap` resource.
func (o VtapOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

// (Updatable) The virtual extensible LAN (VXLAN) network identifier (or VXLAN segment ID) that uniquely identifies the VXLAN.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o VtapOutput) VxlanNetworkIdentifier() pulumi.StringOutput {
	return o.ApplyT(func(v *Vtap) pulumi.StringOutput { return v.VxlanNetworkIdentifier }).(pulumi.StringOutput)
}

type VtapArrayOutput struct{ *pulumi.OutputState }

func (VtapArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Vtap)(nil)).Elem()
}

func (o VtapArrayOutput) ToVtapArrayOutput() VtapArrayOutput {
	return o
}

func (o VtapArrayOutput) ToVtapArrayOutputWithContext(ctx context.Context) VtapArrayOutput {
	return o
}

func (o VtapArrayOutput) Index(i pulumi.IntInput) VtapOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Vtap {
		return vs[0].([]*Vtap)[vs[1].(int)]
	}).(VtapOutput)
}

type VtapMapOutput struct{ *pulumi.OutputState }

func (VtapMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Vtap)(nil)).Elem()
}

func (o VtapMapOutput) ToVtapMapOutput() VtapMapOutput {
	return o
}

func (o VtapMapOutput) ToVtapMapOutputWithContext(ctx context.Context) VtapMapOutput {
	return o
}

func (o VtapMapOutput) MapIndex(k pulumi.StringInput) VtapOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Vtap {
		return vs[0].(map[string]*Vtap)[vs[1].(string)]
	}).(VtapOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*VtapInput)(nil)).Elem(), &Vtap{})
	pulumi.RegisterInputType(reflect.TypeOf((*VtapArrayInput)(nil)).Elem(), VtapArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*VtapMapInput)(nil)).Elem(), VtapMap{})
	pulumi.RegisterOutputType(VtapOutput{})
	pulumi.RegisterOutputType(VtapArrayOutput{})
	pulumi.RegisterOutputType(VtapMapOutput{})
}
