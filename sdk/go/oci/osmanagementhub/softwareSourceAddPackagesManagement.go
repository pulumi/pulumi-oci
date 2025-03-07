// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Software Source Add Packages Management resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Adds packages to a software source. This operation can only be done for custom and versioned custom software sources that are not created using filters.
// For a versioned custom software source, you can only add packages when the source is created. Once content is added to a versioned custom software source, it is immutable.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/osmanagementhub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagementhub.NewSoftwareSourceAddPackagesManagement(ctx, "test_software_source_add_packages_management", &osmanagementhub.SoftwareSourceAddPackagesManagementArgs{
//				Packages:         pulumi.Any(softwareSourceAddPackagesManagementPackages),
//				SoftwareSourceId: pulumi.Any(testSoftwareSource.Id),
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
// SoftwareSourceAddPackagesManagement can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement test_software_source_add_packages_management "id"
// ```
type SoftwareSourceAddPackagesManagement struct {
	pulumi.CustomResourceState

	// List of packages specified by the full package name (NEVRA.rpm).
	Packages pulumi.StringArrayOutput `pulumi:"packages"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SoftwareSourceId pulumi.StringOutput `pulumi:"softwareSourceId"`
}

// NewSoftwareSourceAddPackagesManagement registers a new resource with the given unique name, arguments, and options.
func NewSoftwareSourceAddPackagesManagement(ctx *pulumi.Context,
	name string, args *SoftwareSourceAddPackagesManagementArgs, opts ...pulumi.ResourceOption) (*SoftwareSourceAddPackagesManagement, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Packages == nil {
		return nil, errors.New("invalid value for required argument 'Packages'")
	}
	if args.SoftwareSourceId == nil {
		return nil, errors.New("invalid value for required argument 'SoftwareSourceId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource SoftwareSourceAddPackagesManagement
	err := ctx.RegisterResource("oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSoftwareSourceAddPackagesManagement gets an existing SoftwareSourceAddPackagesManagement resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSoftwareSourceAddPackagesManagement(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SoftwareSourceAddPackagesManagementState, opts ...pulumi.ResourceOption) (*SoftwareSourceAddPackagesManagement, error) {
	var resource SoftwareSourceAddPackagesManagement
	err := ctx.ReadResource("oci:OsManagementHub/softwareSourceAddPackagesManagement:SoftwareSourceAddPackagesManagement", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SoftwareSourceAddPackagesManagement resources.
type softwareSourceAddPackagesManagementState struct {
	// List of packages specified by the full package name (NEVRA.rpm).
	Packages []string `pulumi:"packages"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SoftwareSourceId *string `pulumi:"softwareSourceId"`
}

type SoftwareSourceAddPackagesManagementState struct {
	// List of packages specified by the full package name (NEVRA.rpm).
	Packages pulumi.StringArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SoftwareSourceId pulumi.StringPtrInput
}

func (SoftwareSourceAddPackagesManagementState) ElementType() reflect.Type {
	return reflect.TypeOf((*softwareSourceAddPackagesManagementState)(nil)).Elem()
}

type softwareSourceAddPackagesManagementArgs struct {
	// List of packages specified by the full package name (NEVRA.rpm).
	Packages []string `pulumi:"packages"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SoftwareSourceId string `pulumi:"softwareSourceId"`
}

// The set of arguments for constructing a SoftwareSourceAddPackagesManagement resource.
type SoftwareSourceAddPackagesManagementArgs struct {
	// List of packages specified by the full package name (NEVRA.rpm).
	Packages pulumi.StringArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	SoftwareSourceId pulumi.StringInput
}

func (SoftwareSourceAddPackagesManagementArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*softwareSourceAddPackagesManagementArgs)(nil)).Elem()
}

type SoftwareSourceAddPackagesManagementInput interface {
	pulumi.Input

	ToSoftwareSourceAddPackagesManagementOutput() SoftwareSourceAddPackagesManagementOutput
	ToSoftwareSourceAddPackagesManagementOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementOutput
}

func (*SoftwareSourceAddPackagesManagement) ElementType() reflect.Type {
	return reflect.TypeOf((**SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (i *SoftwareSourceAddPackagesManagement) ToSoftwareSourceAddPackagesManagementOutput() SoftwareSourceAddPackagesManagementOutput {
	return i.ToSoftwareSourceAddPackagesManagementOutputWithContext(context.Background())
}

func (i *SoftwareSourceAddPackagesManagement) ToSoftwareSourceAddPackagesManagementOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceAddPackagesManagementOutput)
}

// SoftwareSourceAddPackagesManagementArrayInput is an input type that accepts SoftwareSourceAddPackagesManagementArray and SoftwareSourceAddPackagesManagementArrayOutput values.
// You can construct a concrete instance of `SoftwareSourceAddPackagesManagementArrayInput` via:
//
//	SoftwareSourceAddPackagesManagementArray{ SoftwareSourceAddPackagesManagementArgs{...} }
type SoftwareSourceAddPackagesManagementArrayInput interface {
	pulumi.Input

	ToSoftwareSourceAddPackagesManagementArrayOutput() SoftwareSourceAddPackagesManagementArrayOutput
	ToSoftwareSourceAddPackagesManagementArrayOutputWithContext(context.Context) SoftwareSourceAddPackagesManagementArrayOutput
}

type SoftwareSourceAddPackagesManagementArray []SoftwareSourceAddPackagesManagementInput

func (SoftwareSourceAddPackagesManagementArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (i SoftwareSourceAddPackagesManagementArray) ToSoftwareSourceAddPackagesManagementArrayOutput() SoftwareSourceAddPackagesManagementArrayOutput {
	return i.ToSoftwareSourceAddPackagesManagementArrayOutputWithContext(context.Background())
}

func (i SoftwareSourceAddPackagesManagementArray) ToSoftwareSourceAddPackagesManagementArrayOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceAddPackagesManagementArrayOutput)
}

// SoftwareSourceAddPackagesManagementMapInput is an input type that accepts SoftwareSourceAddPackagesManagementMap and SoftwareSourceAddPackagesManagementMapOutput values.
// You can construct a concrete instance of `SoftwareSourceAddPackagesManagementMapInput` via:
//
//	SoftwareSourceAddPackagesManagementMap{ "key": SoftwareSourceAddPackagesManagementArgs{...} }
type SoftwareSourceAddPackagesManagementMapInput interface {
	pulumi.Input

	ToSoftwareSourceAddPackagesManagementMapOutput() SoftwareSourceAddPackagesManagementMapOutput
	ToSoftwareSourceAddPackagesManagementMapOutputWithContext(context.Context) SoftwareSourceAddPackagesManagementMapOutput
}

type SoftwareSourceAddPackagesManagementMap map[string]SoftwareSourceAddPackagesManagementInput

func (SoftwareSourceAddPackagesManagementMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (i SoftwareSourceAddPackagesManagementMap) ToSoftwareSourceAddPackagesManagementMapOutput() SoftwareSourceAddPackagesManagementMapOutput {
	return i.ToSoftwareSourceAddPackagesManagementMapOutputWithContext(context.Background())
}

func (i SoftwareSourceAddPackagesManagementMap) ToSoftwareSourceAddPackagesManagementMapOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(SoftwareSourceAddPackagesManagementMapOutput)
}

type SoftwareSourceAddPackagesManagementOutput struct{ *pulumi.OutputState }

func (SoftwareSourceAddPackagesManagementOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (o SoftwareSourceAddPackagesManagementOutput) ToSoftwareSourceAddPackagesManagementOutput() SoftwareSourceAddPackagesManagementOutput {
	return o
}

func (o SoftwareSourceAddPackagesManagementOutput) ToSoftwareSourceAddPackagesManagementOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementOutput {
	return o
}

// List of packages specified by the full package name (NEVRA.rpm).
func (o SoftwareSourceAddPackagesManagementOutput) Packages() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *SoftwareSourceAddPackagesManagement) pulumi.StringArrayOutput { return v.Packages }).(pulumi.StringArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o SoftwareSourceAddPackagesManagementOutput) SoftwareSourceId() pulumi.StringOutput {
	return o.ApplyT(func(v *SoftwareSourceAddPackagesManagement) pulumi.StringOutput { return v.SoftwareSourceId }).(pulumi.StringOutput)
}

type SoftwareSourceAddPackagesManagementArrayOutput struct{ *pulumi.OutputState }

func (SoftwareSourceAddPackagesManagementArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (o SoftwareSourceAddPackagesManagementArrayOutput) ToSoftwareSourceAddPackagesManagementArrayOutput() SoftwareSourceAddPackagesManagementArrayOutput {
	return o
}

func (o SoftwareSourceAddPackagesManagementArrayOutput) ToSoftwareSourceAddPackagesManagementArrayOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementArrayOutput {
	return o
}

func (o SoftwareSourceAddPackagesManagementArrayOutput) Index(i pulumi.IntInput) SoftwareSourceAddPackagesManagementOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *SoftwareSourceAddPackagesManagement {
		return vs[0].([]*SoftwareSourceAddPackagesManagement)[vs[1].(int)]
	}).(SoftwareSourceAddPackagesManagementOutput)
}

type SoftwareSourceAddPackagesManagementMapOutput struct{ *pulumi.OutputState }

func (SoftwareSourceAddPackagesManagementMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*SoftwareSourceAddPackagesManagement)(nil)).Elem()
}

func (o SoftwareSourceAddPackagesManagementMapOutput) ToSoftwareSourceAddPackagesManagementMapOutput() SoftwareSourceAddPackagesManagementMapOutput {
	return o
}

func (o SoftwareSourceAddPackagesManagementMapOutput) ToSoftwareSourceAddPackagesManagementMapOutputWithContext(ctx context.Context) SoftwareSourceAddPackagesManagementMapOutput {
	return o
}

func (o SoftwareSourceAddPackagesManagementMapOutput) MapIndex(k pulumi.StringInput) SoftwareSourceAddPackagesManagementOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *SoftwareSourceAddPackagesManagement {
		return vs[0].(map[string]*SoftwareSourceAddPackagesManagement)[vs[1].(string)]
	}).(SoftwareSourceAddPackagesManagementOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*SoftwareSourceAddPackagesManagementInput)(nil)).Elem(), &SoftwareSourceAddPackagesManagement{})
	pulumi.RegisterInputType(reflect.TypeOf((*SoftwareSourceAddPackagesManagementArrayInput)(nil)).Elem(), SoftwareSourceAddPackagesManagementArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*SoftwareSourceAddPackagesManagementMapInput)(nil)).Elem(), SoftwareSourceAddPackagesManagementMap{})
	pulumi.RegisterOutputType(SoftwareSourceAddPackagesManagementOutput{})
	pulumi.RegisterOutputType(SoftwareSourceAddPackagesManagementArrayOutput{})
	pulumi.RegisterOutputType(SoftwareSourceAddPackagesManagementMapOutput{})
}
