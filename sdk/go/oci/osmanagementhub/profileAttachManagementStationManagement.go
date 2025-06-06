// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Profile Attach Management Station Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Attaches the specified management station to a profile.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/osmanagementhub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagementhub.NewProfileAttachManagementStationManagement(ctx, "test_profile_attach_management_station_management", &osmanagementhub.ProfileAttachManagementStationManagementArgs{
//				ManagementStationId: pulumi.Any(testManagementStation.Id),
//				ProfileId:           pulumi.Any(testProfile.Id),
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
// ProfileAttachManagementStationManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement test_profile_attach_management_station_management "id"
// ```
type ProfileAttachManagementStationManagement struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
	ManagementStationId pulumi.StringOutput `pulumi:"managementStationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProfileId pulumi.StringOutput `pulumi:"profileId"`
}

// NewProfileAttachManagementStationManagement registers a new resource with the given unique name, arguments, and options.
func NewProfileAttachManagementStationManagement(ctx *pulumi.Context,
	name string, args *ProfileAttachManagementStationManagementArgs, opts ...pulumi.ResourceOption) (*ProfileAttachManagementStationManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManagementStationId == nil {
		return nil, errors.New("invalid value for required argument 'ManagementStationId'")
	}
	if args.ProfileId == nil {
		return nil, errors.New("invalid value for required argument 'ProfileId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ProfileAttachManagementStationManagement
	err := ctx.RegisterResource("oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetProfileAttachManagementStationManagement gets an existing ProfileAttachManagementStationManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetProfileAttachManagementStationManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ProfileAttachManagementStationManagementState, opts ...pulumi.ResourceOption) (*ProfileAttachManagementStationManagement, error) {
	var resource ProfileAttachManagementStationManagement
	err := ctx.ReadResource("oci:OsManagementHub/profileAttachManagementStationManagement:ProfileAttachManagementStationManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ProfileAttachManagementStationManagement resources.
type profileAttachManagementStationManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
	ManagementStationId *string `pulumi:"managementStationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProfileId *string `pulumi:"profileId"`
}

type ProfileAttachManagementStationManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
	ManagementStationId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProfileId pulumi.StringPtrInput
}

func (ProfileAttachManagementStationManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*profileAttachManagementStationManagementState)(nil)).Elem()
}

type profileAttachManagementStationManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
	ManagementStationId string `pulumi:"managementStationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProfileId string `pulumi:"profileId"`
}

// The set of arguments for constructing a ProfileAttachManagementStationManagement resource.
type ProfileAttachManagementStationManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
	ManagementStationId pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProfileId pulumi.StringInput
}

func (ProfileAttachManagementStationManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*profileAttachManagementStationManagementArgs)(nil)).Elem()
}

type ProfileAttachManagementStationManagementInput interface {
	pulumi.Input

	ToProfileAttachManagementStationManagementOutput() ProfileAttachManagementStationManagementOutput
	ToProfileAttachManagementStationManagementOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementOutput
}

func (*ProfileAttachManagementStationManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (i *ProfileAttachManagementStationManagement) ToProfileAttachManagementStationManagementOutput() ProfileAttachManagementStationManagementOutput {
	return i.ToProfileAttachManagementStationManagementOutputWithContext(context.Background())
}

func (i *ProfileAttachManagementStationManagement) ToProfileAttachManagementStationManagementOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProfileAttachManagementStationManagementOutput)
}

// ProfileAttachManagementStationManagementArrayInput is an input type that accepts ProfileAttachManagementStationManagementArray and ProfileAttachManagementStationManagementArrayOutput values.
// You can construct a concrete instance of `ProfileAttachManagementStationManagementArrayInput` via:
//
//	ProfileAttachManagementStationManagementArray{ ProfileAttachManagementStationManagementArgs{...} }
type ProfileAttachManagementStationManagementArrayInput interface {
	pulumi.Input

	ToProfileAttachManagementStationManagementArrayOutput() ProfileAttachManagementStationManagementArrayOutput
	ToProfileAttachManagementStationManagementArrayOutputWithContext(context.Context) ProfileAttachManagementStationManagementArrayOutput
}

type ProfileAttachManagementStationManagementArray []ProfileAttachManagementStationManagementInput

func (ProfileAttachManagementStationManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (i ProfileAttachManagementStationManagementArray) ToProfileAttachManagementStationManagementArrayOutput() ProfileAttachManagementStationManagementArrayOutput {
	return i.ToProfileAttachManagementStationManagementArrayOutputWithContext(context.Background())
}

func (i ProfileAttachManagementStationManagementArray) ToProfileAttachManagementStationManagementArrayOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProfileAttachManagementStationManagementArrayOutput)
}

// ProfileAttachManagementStationManagementMapInput is an input type that accepts ProfileAttachManagementStationManagementMap and ProfileAttachManagementStationManagementMapOutput values.
// You can construct a concrete instance of `ProfileAttachManagementStationManagementMapInput` via:
//
//	ProfileAttachManagementStationManagementMap{ "key": ProfileAttachManagementStationManagementArgs{...} }
type ProfileAttachManagementStationManagementMapInput interface {
	pulumi.Input

	ToProfileAttachManagementStationManagementMapOutput() ProfileAttachManagementStationManagementMapOutput
	ToProfileAttachManagementStationManagementMapOutputWithContext(context.Context) ProfileAttachManagementStationManagementMapOutput
}

type ProfileAttachManagementStationManagementMap map[string]ProfileAttachManagementStationManagementInput

func (ProfileAttachManagementStationManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (i ProfileAttachManagementStationManagementMap) ToProfileAttachManagementStationManagementMapOutput() ProfileAttachManagementStationManagementMapOutput {
	return i.ToProfileAttachManagementStationManagementMapOutputWithContext(context.Background())
}

func (i ProfileAttachManagementStationManagementMap) ToProfileAttachManagementStationManagementMapOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProfileAttachManagementStationManagementMapOutput)
}

type ProfileAttachManagementStationManagementOutput struct{ *pulumi.OutputState }

func (ProfileAttachManagementStationManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (o ProfileAttachManagementStationManagementOutput) ToProfileAttachManagementStationManagementOutput() ProfileAttachManagementStationManagementOutput {
	return o
}

func (o ProfileAttachManagementStationManagementOutput) ToProfileAttachManagementStationManagementOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station that the instance will be associated with.
func (o ProfileAttachManagementStationManagementOutput) ManagementStationId() pulumi.StringOutput {
	return o.ApplyT(func(v *ProfileAttachManagementStationManagement) pulumi.StringOutput { return v.ManagementStationId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the registration profile.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ProfileAttachManagementStationManagementOutput) ProfileId() pulumi.StringOutput {
	return o.ApplyT(func(v *ProfileAttachManagementStationManagement) pulumi.StringOutput { return v.ProfileId }).(pulumi.StringOutput)
}

type ProfileAttachManagementStationManagementArrayOutput struct{ *pulumi.OutputState }

func (ProfileAttachManagementStationManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (o ProfileAttachManagementStationManagementArrayOutput) ToProfileAttachManagementStationManagementArrayOutput() ProfileAttachManagementStationManagementArrayOutput {
	return o
}

func (o ProfileAttachManagementStationManagementArrayOutput) ToProfileAttachManagementStationManagementArrayOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementArrayOutput {
	return o
}

func (o ProfileAttachManagementStationManagementArrayOutput) Index(i pulumi.IntInput) ProfileAttachManagementStationManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ProfileAttachManagementStationManagement {
		return vs[0].([]*ProfileAttachManagementStationManagement)[vs[1].(int)]
	}).(ProfileAttachManagementStationManagementOutput)
}

type ProfileAttachManagementStationManagementMapOutput struct{ *pulumi.OutputState }

func (ProfileAttachManagementStationManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProfileAttachManagementStationManagement)(nil)).Elem()
}

func (o ProfileAttachManagementStationManagementMapOutput) ToProfileAttachManagementStationManagementMapOutput() ProfileAttachManagementStationManagementMapOutput {
	return o
}

func (o ProfileAttachManagementStationManagementMapOutput) ToProfileAttachManagementStationManagementMapOutputWithContext(ctx context.Context) ProfileAttachManagementStationManagementMapOutput {
	return o
}

func (o ProfileAttachManagementStationManagementMapOutput) MapIndex(k pulumi.StringInput) ProfileAttachManagementStationManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ProfileAttachManagementStationManagement {
		return vs[0].(map[string]*ProfileAttachManagementStationManagement)[vs[1].(string)]
	}).(ProfileAttachManagementStationManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ProfileAttachManagementStationManagementInput)(nil)).Elem(), &ProfileAttachManagementStationManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProfileAttachManagementStationManagementArrayInput)(nil)).Elem(), ProfileAttachManagementStationManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProfileAttachManagementStationManagementMapInput)(nil)).Elem(), ProfileAttachManagementStationManagementMap{})
	pulumi.RegisterOutputType(ProfileAttachManagementStationManagementOutput{})
	pulumi.RegisterOutputType(ProfileAttachManagementStationManagementArrayOutput{})
	pulumi.RegisterOutputType(ProfileAttachManagementStationManagementMapOutput{})
}
