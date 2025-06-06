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

// This resource provides the Managed Instance Update Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Updates a package on a managed instance.
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
//			_, err := osmanagementhub.NewManagedInstanceUpdatePackagesManagement(ctx, "test_managed_instance_update_packages_management", &osmanagementhub.ManagedInstanceUpdatePackagesManagementArgs{
//				ManagedInstanceId: pulumi.Any(testManagedInstance.Id),
//				PackageNames:      pulumi.Any(managedInstanceUpdatePackagesManagementPackageNames),
//				UpdateTypes:       pulumi.Any(managedInstanceUpdatePackagesManagementUpdateTypes),
//				WorkRequestDetails: &osmanagementhub.ManagedInstanceUpdatePackagesManagementWorkRequestDetailsArgs{
//					Description: pulumi.Any(managedInstanceUpdatePackagesManagementWorkRequestDetailsDescription),
//					DisplayName: pulumi.Any(managedInstanceUpdatePackagesManagementWorkRequestDetailsDisplayName),
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
// ManagedInstanceUpdatePackagesManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/managedInstanceUpdatePackagesManagement:ManagedInstanceUpdatePackagesManagement test_managed_instance_update_packages_management "id"
// ```
type ManagedInstanceUpdatePackagesManagement struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringOutput `pulumi:"managedInstanceId"`
	// The list of package names.
	PackageNames pulumi.StringArrayOutput `pulumi:"packageNames"`
	// The types of updates to be applied.
	UpdateTypes pulumi.StringArrayOutput `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceUpdatePackagesManagementWorkRequestDetailsOutput `pulumi:"workRequestDetails"`
}

// NewManagedInstanceUpdatePackagesManagement registers a new resource with the given unique name, arguments, and options.
func NewManagedInstanceUpdatePackagesManagement(ctx *pulumi.Context,
	name string, args *ManagedInstanceUpdatePackagesManagementArgs, opts ...pulumi.ResourceOption) (*ManagedInstanceUpdatePackagesManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ManagedInstanceId == nil {
		return nil, errors.New("invalid value for required argument 'ManagedInstanceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ManagedInstanceUpdatePackagesManagement
	err := ctx.RegisterResource("oci:OsManagementHub/managedInstanceUpdatePackagesManagement:ManagedInstanceUpdatePackagesManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetManagedInstanceUpdatePackagesManagement gets an existing ManagedInstanceUpdatePackagesManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetManagedInstanceUpdatePackagesManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ManagedInstanceUpdatePackagesManagementState, opts ...pulumi.ResourceOption) (*ManagedInstanceUpdatePackagesManagement, error) {
	var resource ManagedInstanceUpdatePackagesManagement
	err := ctx.ReadResource("oci:OsManagementHub/managedInstanceUpdatePackagesManagement:ManagedInstanceUpdatePackagesManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ManagedInstanceUpdatePackagesManagement resources.
type managedInstanceUpdatePackagesManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The list of package names.
	PackageNames []string `pulumi:"packageNames"`
	// The types of updates to be applied.
	UpdateTypes []string `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceUpdatePackagesManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

type ManagedInstanceUpdatePackagesManagementState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringPtrInput
	// The list of package names.
	PackageNames pulumi.StringArrayInput
	// The types of updates to be applied.
	UpdateTypes pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceUpdatePackagesManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceUpdatePackagesManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceUpdatePackagesManagementState)(nil)).Elem()
}

type managedInstanceUpdatePackagesManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId string `pulumi:"managedInstanceId"`
	// The list of package names.
	PackageNames []string `pulumi:"packageNames"`
	// The types of updates to be applied.
	UpdateTypes []string `pulumi:"updateTypes"`
	// Provides the name and description of the job.
	WorkRequestDetails *ManagedInstanceUpdatePackagesManagementWorkRequestDetails `pulumi:"workRequestDetails"`
}

// The set of arguments for constructing a ManagedInstanceUpdatePackagesManagement resource.
type ManagedInstanceUpdatePackagesManagementArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	ManagedInstanceId pulumi.StringInput
	// The list of package names.
	PackageNames pulumi.StringArrayInput
	// The types of updates to be applied.
	UpdateTypes pulumi.StringArrayInput
	// Provides the name and description of the job.
	WorkRequestDetails ManagedInstanceUpdatePackagesManagementWorkRequestDetailsPtrInput
}

func (ManagedInstanceUpdatePackagesManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*managedInstanceUpdatePackagesManagementArgs)(nil)).Elem()
}

type ManagedInstanceUpdatePackagesManagementInput interface {
	pulumi.Input

	ToManagedInstanceUpdatePackagesManagementOutput() ManagedInstanceUpdatePackagesManagementOutput
	ToManagedInstanceUpdatePackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementOutput
}

func (*ManagedInstanceUpdatePackagesManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (i *ManagedInstanceUpdatePackagesManagement) ToManagedInstanceUpdatePackagesManagementOutput() ManagedInstanceUpdatePackagesManagementOutput {
	return i.ToManagedInstanceUpdatePackagesManagementOutputWithContext(context.Background())
}

func (i *ManagedInstanceUpdatePackagesManagement) ToManagedInstanceUpdatePackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceUpdatePackagesManagementOutput)
}

// ManagedInstanceUpdatePackagesManagementArrayInput is an input type that accepts ManagedInstanceUpdatePackagesManagementArray and ManagedInstanceUpdatePackagesManagementArrayOutput values.
// You can construct a concrete instance of `ManagedInstanceUpdatePackagesManagementArrayInput` via:
//
//	ManagedInstanceUpdatePackagesManagementArray{ ManagedInstanceUpdatePackagesManagementArgs{...} }
type ManagedInstanceUpdatePackagesManagementArrayInput interface {
	pulumi.Input

	ToManagedInstanceUpdatePackagesManagementArrayOutput() ManagedInstanceUpdatePackagesManagementArrayOutput
	ToManagedInstanceUpdatePackagesManagementArrayOutputWithContext(context.Context) ManagedInstanceUpdatePackagesManagementArrayOutput
}

type ManagedInstanceUpdatePackagesManagementArray []ManagedInstanceUpdatePackagesManagementInput

func (ManagedInstanceUpdatePackagesManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (i ManagedInstanceUpdatePackagesManagementArray) ToManagedInstanceUpdatePackagesManagementArrayOutput() ManagedInstanceUpdatePackagesManagementArrayOutput {
	return i.ToManagedInstanceUpdatePackagesManagementArrayOutputWithContext(context.Background())
}

func (i ManagedInstanceUpdatePackagesManagementArray) ToManagedInstanceUpdatePackagesManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceUpdatePackagesManagementArrayOutput)
}

// ManagedInstanceUpdatePackagesManagementMapInput is an input type that accepts ManagedInstanceUpdatePackagesManagementMap and ManagedInstanceUpdatePackagesManagementMapOutput values.
// You can construct a concrete instance of `ManagedInstanceUpdatePackagesManagementMapInput` via:
//
//	ManagedInstanceUpdatePackagesManagementMap{ "key": ManagedInstanceUpdatePackagesManagementArgs{...} }
type ManagedInstanceUpdatePackagesManagementMapInput interface {
	pulumi.Input

	ToManagedInstanceUpdatePackagesManagementMapOutput() ManagedInstanceUpdatePackagesManagementMapOutput
	ToManagedInstanceUpdatePackagesManagementMapOutputWithContext(context.Context) ManagedInstanceUpdatePackagesManagementMapOutput
}

type ManagedInstanceUpdatePackagesManagementMap map[string]ManagedInstanceUpdatePackagesManagementInput

func (ManagedInstanceUpdatePackagesManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (i ManagedInstanceUpdatePackagesManagementMap) ToManagedInstanceUpdatePackagesManagementMapOutput() ManagedInstanceUpdatePackagesManagementMapOutput {
	return i.ToManagedInstanceUpdatePackagesManagementMapOutputWithContext(context.Background())
}

func (i ManagedInstanceUpdatePackagesManagementMap) ToManagedInstanceUpdatePackagesManagementMapOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ManagedInstanceUpdatePackagesManagementMapOutput)
}

type ManagedInstanceUpdatePackagesManagementOutput struct{ *pulumi.OutputState }

func (ManagedInstanceUpdatePackagesManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceUpdatePackagesManagementOutput) ToManagedInstanceUpdatePackagesManagementOutput() ManagedInstanceUpdatePackagesManagementOutput {
	return o
}

func (o ManagedInstanceUpdatePackagesManagementOutput) ToManagedInstanceUpdatePackagesManagementOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
func (o ManagedInstanceUpdatePackagesManagementOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v *ManagedInstanceUpdatePackagesManagement) pulumi.StringOutput { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

// The list of package names.
func (o ManagedInstanceUpdatePackagesManagementOutput) PackageNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ManagedInstanceUpdatePackagesManagement) pulumi.StringArrayOutput { return v.PackageNames }).(pulumi.StringArrayOutput)
}

// The types of updates to be applied.
func (o ManagedInstanceUpdatePackagesManagementOutput) UpdateTypes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ManagedInstanceUpdatePackagesManagement) pulumi.StringArrayOutput { return v.UpdateTypes }).(pulumi.StringArrayOutput)
}

// Provides the name and description of the job.
func (o ManagedInstanceUpdatePackagesManagementOutput) WorkRequestDetails() ManagedInstanceUpdatePackagesManagementWorkRequestDetailsOutput {
	return o.ApplyT(func(v *ManagedInstanceUpdatePackagesManagement) ManagedInstanceUpdatePackagesManagementWorkRequestDetailsOutput {
		return v.WorkRequestDetails
	}).(ManagedInstanceUpdatePackagesManagementWorkRequestDetailsOutput)
}

type ManagedInstanceUpdatePackagesManagementArrayOutput struct{ *pulumi.OutputState }

func (ManagedInstanceUpdatePackagesManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceUpdatePackagesManagementArrayOutput) ToManagedInstanceUpdatePackagesManagementArrayOutput() ManagedInstanceUpdatePackagesManagementArrayOutput {
	return o
}

func (o ManagedInstanceUpdatePackagesManagementArrayOutput) ToManagedInstanceUpdatePackagesManagementArrayOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementArrayOutput {
	return o
}

func (o ManagedInstanceUpdatePackagesManagementArrayOutput) Index(i pulumi.IntInput) ManagedInstanceUpdatePackagesManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ManagedInstanceUpdatePackagesManagement {
		return vs[0].([]*ManagedInstanceUpdatePackagesManagement)[vs[1].(int)]
	}).(ManagedInstanceUpdatePackagesManagementOutput)
}

type ManagedInstanceUpdatePackagesManagementMapOutput struct{ *pulumi.OutputState }

func (ManagedInstanceUpdatePackagesManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ManagedInstanceUpdatePackagesManagement)(nil)).Elem()
}

func (o ManagedInstanceUpdatePackagesManagementMapOutput) ToManagedInstanceUpdatePackagesManagementMapOutput() ManagedInstanceUpdatePackagesManagementMapOutput {
	return o
}

func (o ManagedInstanceUpdatePackagesManagementMapOutput) ToManagedInstanceUpdatePackagesManagementMapOutputWithContext(ctx context.Context) ManagedInstanceUpdatePackagesManagementMapOutput {
	return o
}

func (o ManagedInstanceUpdatePackagesManagementMapOutput) MapIndex(k pulumi.StringInput) ManagedInstanceUpdatePackagesManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ManagedInstanceUpdatePackagesManagement {
		return vs[0].(map[string]*ManagedInstanceUpdatePackagesManagement)[vs[1].(string)]
	}).(ManagedInstanceUpdatePackagesManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceUpdatePackagesManagementInput)(nil)).Elem(), &ManagedInstanceUpdatePackagesManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceUpdatePackagesManagementArrayInput)(nil)).Elem(), ManagedInstanceUpdatePackagesManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ManagedInstanceUpdatePackagesManagementMapInput)(nil)).Elem(), ManagedInstanceUpdatePackagesManagementMap{})
	pulumi.RegisterOutputType(ManagedInstanceUpdatePackagesManagementOutput{})
	pulumi.RegisterOutputType(ManagedInstanceUpdatePackagesManagementArrayOutput{})
	pulumi.RegisterOutputType(ManagedInstanceUpdatePackagesManagementMapOutput{})
}
