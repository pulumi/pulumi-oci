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

// This resource provides the Managed Instance Group Update All Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Updates all packages on each managed instance in the specified managed instance group.
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
//			_, err := osmanagementhub.NewManagedInstanceGroupUpdateAllPackagesManagement(ctx, "test_managed_instance_group_update_all_packages_management", &osmanagementhub.ManagedInstanceGroupUpdateAllPackagesManagementArgs{
//				ManagedInstanceGroupId: pulumi.Any(testManagedInstanceGroup.Id),
//				UpdateTypes:            pulumi.Any(managedInstanceGroupUpdateAllPackagesManagementUpdateTypes),
//				WorkRequestDetails: &osmanagementhub.ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsArgs{
//					Description: pulumi.Any(managedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsDescription),
//					DisplayName: pulumi.Any(managedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsDisplayName),
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
// ManagedInstanceGroupUpdateAllPackagesManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/managedInstanceGroupUpdateAllPackagesManagement:ManagedInstanceGroupUpdateAllPackagesManagement test_managed_instance_group_update_all_packages_management "id"
// ```
type ManagedInstanceGroupUpdateAllPackagesManagement struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
	ManagedInstanceGroupId pulumi.StringOutput `pulumi:"managedInstanceGroupId"`
	// The type of updates to be applied.
	UpdateTypes pulumi.StringArrayOutput `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsOutput `pulumi:"workRequestDetails"`
}

// NewManagedInstanceGroupUpdateAllPackagesManagement registers a new resource with the given unique name, arguments, and options.
func NewManagedInstanceGroupUpdateAllPackagesManagement(ctx *pulumi.Context,
	name string, args *ManagedInstanceGroupUpdateAllPackagesManagementArgs, opts ...pulumi.ResourceOption) (*ManagedInstanceGroupUpdateAllPackagesManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManagedInstanceGroupId == nil {
		return nil, errors.New("invalid value for required argument 'ManagedInstanceGroupId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ManagedInstanceGroupUpdateAllPackagesManagement
	err := ctx.RegisterResource("oci:OsManagementHub/managedInstanceGroupUpdateAllPackagesManagement:ManagedInstanceGroupUpdateAllPackagesManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetManagedInstanceGroupUpdateAllPackagesManagement gets an existing ManagedInstanceGroupUpdateAllPackagesManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetManagedInstanceGroupUpdateAllPackagesManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ManagedInstanceGroupUpdateAllPackagesManagementState, opts ...pulumi.ResourceOption) (*ManagedInstanceGroupUpdateAllPackagesManagement, error) {
	var resource ManagedInstanceGroupUpdateAllPackagesManagement
	err := ctx.ReadResource("oci:OsManagementHub/managedInstanceGroupUpdateAllPackagesManagement:ManagedInstanceGroupUpdateAllPackagesManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ManagedInstanceGroupUpdateAllPackagesManagement resources.
type managedInstanceGroupUpdateAllPackagesManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
	ManagedInstanceGroupId *string `pulumi:"managedInstanceGroupId"`
	// The type of updates to be applied.
	UpdateTypes []string `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

type ManagedInstanceGroupUpdateAllPackagesManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
	ManagedInstanceGroupId pulumi.StringPtrInput
	// The type of updates to be applied.
	UpdateTypes pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceGroupUpdateAllPackagesManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceGroupUpdateAllPackagesManagementState)(nil)).Elem()
}

type managedInstanceGroupUpdateAllPackagesManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
	ManagedInstanceGroupId string `pulumi:"managedInstanceGroupId"`
	// The type of updates to be applied.
	UpdateTypes []string `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

// The set of arguments for constructing a ManagedInstanceGroupUpdateAllPackagesManagement resource.
type ManagedInstanceGroupUpdateAllPackagesManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
	ManagedInstanceGroupId pulumi.StringInput
	// The type of updates to be applied.
	UpdateTypes pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceGroupUpdateAllPackagesManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceGroupUpdateAllPackagesManagementArgs)(nil)).Elem()
}

type ManagedInstanceGroupUpdateAllPackagesManagementInput interface {
	pulumi.Input

	ToManagedInstanceGroupUpdateAllPackagesManagementOutput() ManagedInstanceGroupUpdateAllPackagesManagementOutput
	ToManagedInstanceGroupUpdateAllPackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementOutput
}

func (*ManagedInstanceGroupUpdateAllPackagesManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (i *ManagedInstanceGroupUpdateAllPackagesManagement) ToManagedInstanceGroupUpdateAllPackagesManagementOutput() ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return i.ToManagedInstanceGroupUpdateAllPackagesManagementOutputWithContext(context.Background())
}

func (i *ManagedInstanceGroupUpdateAllPackagesManagement) ToManagedInstanceGroupUpdateAllPackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceGroupUpdateAllPackagesManagementOutput)
}

// ManagedInstanceGroupUpdateAllPackagesManagementArrayInput is an input type that accepts ManagedInstanceGroupUpdateAllPackagesManagementArray and ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput values.
// You can construct a concrete instance of `ManagedInstanceGroupUpdateAllPackagesManagementArrayInput` via:
//
//	ManagedInstanceGroupUpdateAllPackagesManagementArray{ ManagedInstanceGroupUpdateAllPackagesManagementArgs{...} }
type ManagedInstanceGroupUpdateAllPackagesManagementArrayInput interface {
	pulumi.Input

	ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutput() ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput
	ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutputWithContext(context.Context) ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput
}

type ManagedInstanceGroupUpdateAllPackagesManagementArray []ManagedInstanceGroupUpdateAllPackagesManagementInput

func (ManagedInstanceGroupUpdateAllPackagesManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (i ManagedInstanceGroupUpdateAllPackagesManagementArray) ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutput() ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput {
	return i.ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutputWithContext(context.Background())
}

func (i ManagedInstanceGroupUpdateAllPackagesManagementArray) ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput)
}

// ManagedInstanceGroupUpdateAllPackagesManagementMapInput is an input type that accepts ManagedInstanceGroupUpdateAllPackagesManagementMap and ManagedInstanceGroupUpdateAllPackagesManagementMapOutput values.
// You can construct a concrete instance of `ManagedInstanceGroupUpdateAllPackagesManagementMapInput` via:
//
//	ManagedInstanceGroupUpdateAllPackagesManagementMap{ "key": ManagedInstanceGroupUpdateAllPackagesManagementArgs{...} }
type ManagedInstanceGroupUpdateAllPackagesManagementMapInput interface {
	pulumi.Input

	ToManagedInstanceGroupUpdateAllPackagesManagementMapOutput() ManagedInstanceGroupUpdateAllPackagesManagementMapOutput
	ToManagedInstanceGroupUpdateAllPackagesManagementMapOutputWithContext(context.Context) ManagedInstanceGroupUpdateAllPackagesManagementMapOutput
}

type ManagedInstanceGroupUpdateAllPackagesManagementMap map[string]ManagedInstanceGroupUpdateAllPackagesManagementInput

func (ManagedInstanceGroupUpdateAllPackagesManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (i ManagedInstanceGroupUpdateAllPackagesManagementMap) ToManagedInstanceGroupUpdateAllPackagesManagementMapOutput() ManagedInstanceGroupUpdateAllPackagesManagementMapOutput {
	return i.ToManagedInstanceGroupUpdateAllPackagesManagementMapOutputWithContext(context.Background())
}

func (i ManagedInstanceGroupUpdateAllPackagesManagementMap) ToManagedInstanceGroupUpdateAllPackagesManagementMapOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceGroupUpdateAllPackagesManagementMapOutput)
}

type ManagedInstanceGroupUpdateAllPackagesManagementOutput struct{ *pulumi.OutputState }

func (ManagedInstanceGroupUpdateAllPackagesManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementOutput) ToManagedInstanceGroupUpdateAllPackagesManagementOutput() ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return o
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementOutput) ToManagedInstanceGroupUpdateAllPackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance group.
func (o ManagedInstanceGroupUpdateAllPackagesManagementOutput) ManagedInstanceGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedInstanceGroupUpdateAllPackagesManagement) pulumi.StringOutput {
		return v.ManagedInstanceGroupId
	}).(pulumi.StringOutput)
}

// The type of updates to be applied.
func (o ManagedInstanceGroupUpdateAllPackagesManagementOutput) UpdateTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ManagedInstanceGroupUpdateAllPackagesManagement) pulumi.StringArrayOutput {
		return v.UpdateTypes
	}).(pulumi.StringArrayOutput)
}

// Provides the name and description of the job.
func (o ManagedInstanceGroupUpdateAllPackagesManagementOutput) WorkRequestDetails() ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsOutput {
	return o.ApplyT(func(v *ManagedInstanceGroupUpdateAllPackagesManagement) ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsOutput {
		return v.WorkRequestDetails
	}).(ManagedInstanceGroupUpdateAllPackagesManagementWorkRequestDetailsOutput)
}

type ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput struct{ *pulumi.OutputState }

func (ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput) ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutput() ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput {
	return o
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput) ToManagedInstanceGroupUpdateAllPackagesManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput {
	return o
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput) Index(i pulumi.IntInput) ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ManagedInstanceGroupUpdateAllPackagesManagement {
		return vs[0].([]*ManagedInstanceGroupUpdateAllPackagesManagement)[vs[1].(int)]
	}).(ManagedInstanceGroupUpdateAllPackagesManagementOutput)
}

type ManagedInstanceGroupUpdateAllPackagesManagementMapOutput struct{ *pulumi.OutputState }

func (ManagedInstanceGroupUpdateAllPackagesManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceGroupUpdateAllPackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementMapOutput) ToManagedInstanceGroupUpdateAllPackagesManagementMapOutput() ManagedInstanceGroupUpdateAllPackagesManagementMapOutput {
	return o
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementMapOutput) ToManagedInstanceGroupUpdateAllPackagesManagementMapOutputWithContext(ctx context.Context) ManagedInstanceGroupUpdateAllPackagesManagementMapOutput {
	return o
}

func (o ManagedInstanceGroupUpdateAllPackagesManagementMapOutput) MapIndex(k pulumi.StringInput) ManagedInstanceGroupUpdateAllPackagesManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ManagedInstanceGroupUpdateAllPackagesManagement {
		return vs[0].(map[string]*ManagedInstanceGroupUpdateAllPackagesManagement)[vs[1].(string)]
	}).(ManagedInstanceGroupUpdateAllPackagesManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceGroupUpdateAllPackagesManagementInput)(nil)).Elem(), &ManagedInstanceGroupUpdateAllPackagesManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceGroupUpdateAllPackagesManagementArrayInput)(nil)).Elem(), ManagedInstanceGroupUpdateAllPackagesManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceGroupUpdateAllPackagesManagementMapInput)(nil)).Elem(), ManagedInstanceGroupUpdateAllPackagesManagementMap{})
	pulumi.RegisterOutputType(ManagedInstanceGroupUpdateAllPackagesManagementOutput{})
	pulumi.RegisterOutputType(ManagedInstanceGroupUpdateAllPackagesManagementArrayOutput{})
	pulumi.RegisterOutputType(ManagedInstanceGroupUpdateAllPackagesManagementMapOutput{})
}
