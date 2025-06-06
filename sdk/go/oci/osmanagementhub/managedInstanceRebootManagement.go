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

// This resource provides the Managed Instance Reboot Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Initiates a reboot of the specified managed instance. You can also specify the number of minutes the service
// waits before marking the reboot operation as failed.
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
//			_, err := osmanagementhub.NewManagedInstanceRebootManagement(ctx, "test_managed_instance_reboot_management", &osmanagementhub.ManagedInstanceRebootManagementArgs{
//				ManagedInstanceId:   pulumi.Any(testManagedInstance.Id),
//				RebootTimeoutInMins: pulumi.Any(managedInstanceRebootManagementRebootTimeoutInMins),
//				WorkRequestDetails: &osmanagementhub.ManagedInstanceRebootManagementWorkRequestDetailsArgs{
//					Description: pulumi.Any(managedInstanceRebootManagementWorkRequestDetailsDescription),
//					DisplayName: pulumi.Any(managedInstanceRebootManagementWorkRequestDetailsDisplayName),
//				},
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
// ManagedInstanceRebootManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/managedInstanceRebootManagement:ManagedInstanceRebootManagement test_managed_instance_reboot_management "id"
// ```
type ManagedInstanceRebootManagement struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringOutput `pulumi:"managedInstanceId"`
	// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
	RebootTimeoutInMins pulumi.IntOutput `pulumi:"rebootTimeoutInMins"`
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceRebootManagementWorkRequestDetailsOutput `pulumi:"workRequestDetails"`
}

// NewManagedInstanceRebootManagement registers a new resource with the given unique name, arguments, and options.
func NewManagedInstanceRebootManagement(ctx *pulumi.Context,
	name string, args *ManagedInstanceRebootManagementArgs, opts ...pulumi.ResourceOption) (*ManagedInstanceRebootManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManagedInstanceId == nil {
		return nil, errors.New("invalid value for required argument 'ManagedInstanceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ManagedInstanceRebootManagement
	err := ctx.RegisterResource("oci:OsManagementHub/managedInstanceRebootManagement:ManagedInstanceRebootManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetManagedInstanceRebootManagement gets an existing ManagedInstanceRebootManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetManagedInstanceRebootManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ManagedInstanceRebootManagementState, opts ...pulumi.ResourceOption) (*ManagedInstanceRebootManagement, error) {
	var resource ManagedInstanceRebootManagement
	err := ctx.ReadResource("oci:OsManagementHub/managedInstanceRebootManagement:ManagedInstanceRebootManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ManagedInstanceRebootManagement resources.
type managedInstanceRebootManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
	RebootTimeoutInMins *int `pulumi:"rebootTimeoutInMins"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceRebootManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

type ManagedInstanceRebootManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringPtrInput
	// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
	RebootTimeoutInMins pulumi.IntPtrInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceRebootManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceRebootManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceRebootManagementState)(nil)).Elem()
}

type managedInstanceRebootManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId string `pulumi:"managedInstanceId"`
	// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
	RebootTimeoutInMins *int `pulumi:"rebootTimeoutInMins"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceRebootManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

// The set of arguments for constructing a ManagedInstanceRebootManagement resource.
type ManagedInstanceRebootManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringInput
	// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
	RebootTimeoutInMins pulumi.IntPtrInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceRebootManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceRebootManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceRebootManagementArgs)(nil)).Elem()
}

type ManagedInstanceRebootManagementInput interface {
	pulumi.Input

	ToManagedInstanceRebootManagementOutput() ManagedInstanceRebootManagementOutput
	ToManagedInstanceRebootManagementOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementOutput
}

func (*ManagedInstanceRebootManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceRebootManagement)(nil)).Elem()
}

func (i *ManagedInstanceRebootManagement) ToManagedInstanceRebootManagementOutput() ManagedInstanceRebootManagementOutput {
	return i.ToManagedInstanceRebootManagementOutputWithContext(context.Background())
}

func (i *ManagedInstanceRebootManagement) ToManagedInstanceRebootManagementOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceRebootManagementOutput)
}

// ManagedInstanceRebootManagementArrayInput is an input type that accepts ManagedInstanceRebootManagementArray and ManagedInstanceRebootManagementArrayOutput values.
// You can construct a concrete instance of `ManagedInstanceRebootManagementArrayInput` via:
//
//	ManagedInstanceRebootManagementArray{ ManagedInstanceRebootManagementArgs{...} }
type ManagedInstanceRebootManagementArrayInput interface {
	pulumi.Input

	ToManagedInstanceRebootManagementArrayOutput() ManagedInstanceRebootManagementArrayOutput
	ToManagedInstanceRebootManagementArrayOutputWithContext(context.Context) ManagedInstanceRebootManagementArrayOutput
}

type ManagedInstanceRebootManagementArray []ManagedInstanceRebootManagementInput

func (ManagedInstanceRebootManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceRebootManagement)(nil)).Elem()
}

func (i ManagedInstanceRebootManagementArray) ToManagedInstanceRebootManagementArrayOutput() ManagedInstanceRebootManagementArrayOutput {
	return i.ToManagedInstanceRebootManagementArrayOutputWithContext(context.Background())
}

func (i ManagedInstanceRebootManagementArray) ToManagedInstanceRebootManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceRebootManagementArrayOutput)
}

// ManagedInstanceRebootManagementMapInput is an input type that accepts ManagedInstanceRebootManagementMap and ManagedInstanceRebootManagementMapOutput values.
// You can construct a concrete instance of `ManagedInstanceRebootManagementMapInput` via:
//
//	ManagedInstanceRebootManagementMap{ "key": ManagedInstanceRebootManagementArgs{...} }
type ManagedInstanceRebootManagementMapInput interface {
	pulumi.Input

	ToManagedInstanceRebootManagementMapOutput() ManagedInstanceRebootManagementMapOutput
	ToManagedInstanceRebootManagementMapOutputWithContext(context.Context) ManagedInstanceRebootManagementMapOutput
}

type ManagedInstanceRebootManagementMap map[string]ManagedInstanceRebootManagementInput

func (ManagedInstanceRebootManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceRebootManagement)(nil)).Elem()
}

func (i ManagedInstanceRebootManagementMap) ToManagedInstanceRebootManagementMapOutput() ManagedInstanceRebootManagementMapOutput {
	return i.ToManagedInstanceRebootManagementMapOutputWithContext(context.Background())
}

func (i ManagedInstanceRebootManagementMap) ToManagedInstanceRebootManagementMapOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceRebootManagementMapOutput)
}

type ManagedInstanceRebootManagementOutput struct{ *pulumi.OutputState }

func (ManagedInstanceRebootManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceRebootManagement)(nil)).Elem()
}

func (o ManagedInstanceRebootManagementOutput) ToManagedInstanceRebootManagementOutput() ManagedInstanceRebootManagementOutput {
	return o
}

func (o ManagedInstanceRebootManagementOutput) ToManagedInstanceRebootManagementOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
func (o ManagedInstanceRebootManagementOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedInstanceRebootManagement) pulumi.StringOutput { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

// The number of minutes the service waits for the reboot to complete. If the instance doesn't reboot within this  time, the reboot job status is set to failed.
func (o ManagedInstanceRebootManagementOutput) RebootTimeoutInMins() pulumi.IntOutput {
	return o.ApplyT(func(v *ManagedInstanceRebootManagement) pulumi.IntOutput { return v.RebootTimeoutInMins }).(pulumi.IntOutput)
}

// Provides the name and description of the job.
func (o ManagedInstanceRebootManagementOutput) WorkRequestDetails() ManagedInstanceRebootManagementWorkRequestDetailsOutput {
	return o.ApplyT(func(v *ManagedInstanceRebootManagement) ManagedInstanceRebootManagementWorkRequestDetailsOutput {
		return v.WorkRequestDetails
	}).(ManagedInstanceRebootManagementWorkRequestDetailsOutput)
}

type ManagedInstanceRebootManagementArrayOutput struct{ *pulumi.OutputState }

func (ManagedInstanceRebootManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceRebootManagement)(nil)).Elem()
}

func (o ManagedInstanceRebootManagementArrayOutput) ToManagedInstanceRebootManagementArrayOutput() ManagedInstanceRebootManagementArrayOutput {
	return o
}

func (o ManagedInstanceRebootManagementArrayOutput) ToManagedInstanceRebootManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementArrayOutput {
	return o
}

func (o ManagedInstanceRebootManagementArrayOutput) Index(i pulumi.IntInput) ManagedInstanceRebootManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ManagedInstanceRebootManagement {
		return vs[0].([]*ManagedInstanceRebootManagement)[vs[1].(int)]
	}).(ManagedInstanceRebootManagementOutput)
}

type ManagedInstanceRebootManagementMapOutput struct{ *pulumi.OutputState }

func (ManagedInstanceRebootManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceRebootManagement)(nil)).Elem()
}

func (o ManagedInstanceRebootManagementMapOutput) ToManagedInstanceRebootManagementMapOutput() ManagedInstanceRebootManagementMapOutput {
	return o
}

func (o ManagedInstanceRebootManagementMapOutput) ToManagedInstanceRebootManagementMapOutputWithContext(ctx context.Context) ManagedInstanceRebootManagementMapOutput {
	return o
}

func (o ManagedInstanceRebootManagementMapOutput) MapIndex(k pulumi.StringInput) ManagedInstanceRebootManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ManagedInstanceRebootManagement {
		return vs[0].(map[string]*ManagedInstanceRebootManagement)[vs[1].(string)]
	}).(ManagedInstanceRebootManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceRebootManagementInput)(nil)).Elem(), &ManagedInstanceRebootManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceRebootManagementArrayInput)(nil)).Elem(), ManagedInstanceRebootManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceRebootManagementMapInput)(nil)).Elem(), ManagedInstanceRebootManagementMap{})
	pulumi.RegisterOutputType(ManagedInstanceRebootManagementOutput{})
	pulumi.RegisterOutputType(ManagedInstanceRebootManagementArrayOutput{})
	pulumi.RegisterOutputType(ManagedInstanceRebootManagementMapOutput{})
}
