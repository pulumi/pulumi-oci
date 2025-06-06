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

// This resource provides the Work Request Rerun Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Reruns a failed work for the specified work request [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Rerunning restarts the work on failed targets.
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
//			_, err := osmanagementhub.NewWorkRequestRerunManagement(ctx, "test_work_request_rerun_management", &osmanagementhub.WorkRequestRerunManagementArgs{
//				WorkRequestId:    pulumi.Any(testWorkRequest.Id),
//				ManagedInstances: pulumi.Any(workRequestRerunManagementManagedInstances),
//				WorkRequestDetails: &osmanagementhub.WorkRequestRerunManagementWorkRequestDetailsArgs{
//					Description: pulumi.Any(workRequestRerunManagementWorkRequestDetailsDescription),
//					DisplayName: pulumi.Any(workRequestRerunManagementWorkRequestDetailsDisplayName),
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
// WorkRequestRerunManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/workRequestRerunManagement:WorkRequestRerunManagement test_work_request_rerun_management "id"
// ```
type WorkRequestRerunManagement struct {
	pulumi.CustomResourceState

	// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
	ManagedInstances pulumi.StringArrayOutput `pulumi:"managedInstances"`
	// Provides the name and description of the job.
	WorkRequestDetails WorkRequestRerunManagementWorkRequestDetailsOutput `pulumi:"workRequestDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkRequestId pulumi.StringOutput `pulumi:"workRequestId"`
}

// NewWorkRequestRerunManagement registers a new resource with the given unique name, arguments, and options.
func NewWorkRequestRerunManagement(ctx *pulumi.Context,
	name string, args *WorkRequestRerunManagementArgs, opts ...pulumi.ResourceOption) (*WorkRequestRerunManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.WorkRequestId == nil {
		return nil, errors.New("invalid value for required argument 'WorkRequestId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource WorkRequestRerunManagement
	err := ctx.RegisterResource("oci:OsManagementHub/workRequestRerunManagement:WorkRequestRerunManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetWorkRequestRerunManagement gets an existing WorkRequestRerunManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetWorkRequestRerunManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *WorkRequestRerunManagementState, opts ...pulumi.ResourceOption) (*WorkRequestRerunManagement, error) {
	var resource WorkRequestRerunManagement
	err := ctx.ReadResource("oci:OsManagementHub/workRequestRerunManagement:WorkRequestRerunManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering WorkRequestRerunManagement resources.
type workRequestRerunManagementState struct {
	// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
	ManagedInstances []string `pulumi:"managedInstances"`
	// Provides the name and description of the job.
	WorkRequestDetails *WorkRequestRerunManagementWorkRequestDetails `pulumi:"workRequestDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkRequestId *string `pulumi:"workRequestId"`
}

type WorkRequestRerunManagementState struct {
	// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
	ManagedInstances pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails WorkRequestRerunManagementWorkRequestDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkRequestId pulumi.StringPtrInput
}

func (WorkRequestRerunManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*workRequestRerunManagementState)(nil)).Elem()
}

type workRequestRerunManagementArgs struct {
	// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
	ManagedInstances []string `pulumi:"managedInstances"`
	// Provides the name and description of the job.
	WorkRequestDetails *WorkRequestRerunManagementWorkRequestDetails `pulumi:"workRequestDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkRequestId string `pulumi:"workRequestId"`
}

// The set of arguments for constructing a WorkRequestRerunManagement resource.
type WorkRequestRerunManagementArgs struct {
	// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
	ManagedInstances pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails WorkRequestRerunManagementWorkRequestDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	WorkRequestId pulumi.StringInput
}

func (WorkRequestRerunManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*workRequestRerunManagementArgs)(nil)).Elem()
}

type WorkRequestRerunManagementInput interface {
	pulumi.Input

	ToWorkRequestRerunManagementOutput() WorkRequestRerunManagementOutput
	ToWorkRequestRerunManagementOutputWithContext(ctx context.Context) WorkRequestRerunManagementOutput
}

func (*WorkRequestRerunManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkRequestRerunManagement)(nil)).Elem()
}

func (i *WorkRequestRerunManagement) ToWorkRequestRerunManagementOutput() WorkRequestRerunManagementOutput {
	return i.ToWorkRequestRerunManagementOutputWithContext(context.Background())
}

func (i *WorkRequestRerunManagement) ToWorkRequestRerunManagementOutputWithContext(ctx context.Context) WorkRequestRerunManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkRequestRerunManagementOutput)
}

// WorkRequestRerunManagementArrayInput is an input type that accepts WorkRequestRerunManagementArray and WorkRequestRerunManagementArrayOutput values.
// You can construct a concrete instance of `WorkRequestRerunManagementArrayInput` via:
//
//	WorkRequestRerunManagementArray{ WorkRequestRerunManagementArgs{...} }
type WorkRequestRerunManagementArrayInput interface {
	pulumi.Input

	ToWorkRequestRerunManagementArrayOutput() WorkRequestRerunManagementArrayOutput
	ToWorkRequestRerunManagementArrayOutputWithContext(context.Context) WorkRequestRerunManagementArrayOutput
}

type WorkRequestRerunManagementArray []WorkRequestRerunManagementInput

func (WorkRequestRerunManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkRequestRerunManagement)(nil)).Elem()
}

func (i WorkRequestRerunManagementArray) ToWorkRequestRerunManagementArrayOutput() WorkRequestRerunManagementArrayOutput {
	return i.ToWorkRequestRerunManagementArrayOutputWithContext(context.Background())
}

func (i WorkRequestRerunManagementArray) ToWorkRequestRerunManagementArrayOutputWithContext(ctx context.Context) WorkRequestRerunManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkRequestRerunManagementArrayOutput)
}

// WorkRequestRerunManagementMapInput is an input type that accepts WorkRequestRerunManagementMap and WorkRequestRerunManagementMapOutput values.
// You can construct a concrete instance of `WorkRequestRerunManagementMapInput` via:
//
//	WorkRequestRerunManagementMap{ "key": WorkRequestRerunManagementArgs{...} }
type WorkRequestRerunManagementMapInput interface {
	pulumi.Input

	ToWorkRequestRerunManagementMapOutput() WorkRequestRerunManagementMapOutput
	ToWorkRequestRerunManagementMapOutputWithContext(context.Context) WorkRequestRerunManagementMapOutput
}

type WorkRequestRerunManagementMap map[string]WorkRequestRerunManagementInput

func (WorkRequestRerunManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkRequestRerunManagement)(nil)).Elem()
}

func (i WorkRequestRerunManagementMap) ToWorkRequestRerunManagementMapOutput() WorkRequestRerunManagementMapOutput {
	return i.ToWorkRequestRerunManagementMapOutputWithContext(context.Background())
}

func (i WorkRequestRerunManagementMap) ToWorkRequestRerunManagementMapOutputWithContext(ctx context.Context) WorkRequestRerunManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(WorkRequestRerunManagementMapOutput)
}

type WorkRequestRerunManagementOutput struct{ *pulumi.OutputState }

func (WorkRequestRerunManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**WorkRequestRerunManagement)(nil)).Elem()
}

func (o WorkRequestRerunManagementOutput) ToWorkRequestRerunManagementOutput() WorkRequestRerunManagementOutput {
	return o
}

func (o WorkRequestRerunManagementOutput) ToWorkRequestRerunManagementOutputWithContext(ctx context.Context) WorkRequestRerunManagementOutput {
	return o
}

// List of managed instance [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to affected by the rerun of the work request.
func (o WorkRequestRerunManagementOutput) ManagedInstances() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *WorkRequestRerunManagement) pulumi.StringArrayOutput { return v.ManagedInstances }).(pulumi.StringArrayOutput)
}

// Provides the name and description of the job.
func (o WorkRequestRerunManagementOutput) WorkRequestDetails() WorkRequestRerunManagementWorkRequestDetailsOutput {
	return o.ApplyT(func(v *WorkRequestRerunManagement) WorkRequestRerunManagementWorkRequestDetailsOutput {
		return v.WorkRequestDetails
	}).(WorkRequestRerunManagementWorkRequestDetailsOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the work request.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o WorkRequestRerunManagementOutput) WorkRequestId() pulumi.StringOutput {
	return o.ApplyT(func(v *WorkRequestRerunManagement) pulumi.StringOutput { return v.WorkRequestId }).(pulumi.StringOutput)
}

type WorkRequestRerunManagementArrayOutput struct{ *pulumi.OutputState }

func (WorkRequestRerunManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*WorkRequestRerunManagement)(nil)).Elem()
}

func (o WorkRequestRerunManagementArrayOutput) ToWorkRequestRerunManagementArrayOutput() WorkRequestRerunManagementArrayOutput {
	return o
}

func (o WorkRequestRerunManagementArrayOutput) ToWorkRequestRerunManagementArrayOutputWithContext(ctx context.Context) WorkRequestRerunManagementArrayOutput {
	return o
}

func (o WorkRequestRerunManagementArrayOutput) Index(i pulumi.IntInput) WorkRequestRerunManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *WorkRequestRerunManagement {
		return vs[0].([]*WorkRequestRerunManagement)[vs[1].(int)]
	}).(WorkRequestRerunManagementOutput)
}

type WorkRequestRerunManagementMapOutput struct{ *pulumi.OutputState }

func (WorkRequestRerunManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*WorkRequestRerunManagement)(nil)).Elem()
}

func (o WorkRequestRerunManagementMapOutput) ToWorkRequestRerunManagementMapOutput() WorkRequestRerunManagementMapOutput {
	return o
}

func (o WorkRequestRerunManagementMapOutput) ToWorkRequestRerunManagementMapOutputWithContext(ctx context.Context) WorkRequestRerunManagementMapOutput {
	return o
}

func (o WorkRequestRerunManagementMapOutput) MapIndex(k pulumi.StringInput) WorkRequestRerunManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *WorkRequestRerunManagement {
		return vs[0].(map[string]*WorkRequestRerunManagement)[vs[1].(string)]
	}).(WorkRequestRerunManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*WorkRequestRerunManagementInput)(nil)).Elem(), &WorkRequestRerunManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkRequestRerunManagementArrayInput)(nil)).Elem(), WorkRequestRerunManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*WorkRequestRerunManagementMapInput)(nil)).Elem(), WorkRequestRerunManagementMap{})
	pulumi.RegisterOutputType(WorkRequestRerunManagementOutput{})
	pulumi.RegisterOutputType(WorkRequestRerunManagementArrayOutput{})
	pulumi.RegisterOutputType(WorkRequestRerunManagementMapOutput{})
}
