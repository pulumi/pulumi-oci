// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package artifacts

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Container Configuration resource in Oracle Cloud Infrastructure Artifacts service.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Artifacts"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Artifacts.NewContainerConfiguration(ctx, "testContainerConfiguration", nil)
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
// ContainerConfiguration can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Artifacts/containerConfiguration:ContainerConfiguration test_container_configuration "container/configuration/compartmentId/{compartmentId}"
//
// ```
type ContainerConfiguration struct {
	pulumi.CustomResourceState

	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush pulumi.BoolOutput `pulumi:"isRepositoryCreatedOnFirstPush"`
	// The tenancy namespace used in the container repository path.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
}

// NewContainerConfiguration registers a new resource with the given unique name, arguments, and options.
func NewContainerConfiguration(ctx *pulumi.Context,
	name string, args *ContainerConfigurationArgs, opts ...pulumi.ResourceOption) (*ContainerConfiguration, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.IsRepositoryCreatedOnFirstPush == nil {
		return nil, errors.New("invalid value for required argument 'IsRepositoryCreatedOnFirstPush'")
	}
	var resource ContainerConfiguration
	err := ctx.RegisterResource("oci:Artifacts/containerConfiguration:ContainerConfiguration", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetContainerConfiguration gets an existing ContainerConfiguration resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetContainerConfiguration(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ContainerConfigurationState, opts ...pulumi.ResourceOption) (*ContainerConfiguration, error) {
	var resource ContainerConfiguration
	err := ctx.ReadResource("oci:Artifacts/containerConfiguration:ContainerConfiguration", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ContainerConfiguration resources.
type containerConfigurationState struct {
	CompartmentId *string `pulumi:"compartmentId"`
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush *bool `pulumi:"isRepositoryCreatedOnFirstPush"`
	// The tenancy namespace used in the container repository path.
	Namespace *string `pulumi:"namespace"`
}

type ContainerConfigurationState struct {
	CompartmentId pulumi.StringPtrInput
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush pulumi.BoolPtrInput
	// The tenancy namespace used in the container repository path.
	Namespace pulumi.StringPtrInput
}

func (ContainerConfigurationState) ElementType() reflect.Type {
	return reflect.TypeOf((*containerConfigurationState)(nil)).Elem()
}

type containerConfigurationArgs struct {
	CompartmentId string `pulumi:"compartmentId"`
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush bool `pulumi:"isRepositoryCreatedOnFirstPush"`
}

// The set of arguments for constructing a ContainerConfiguration resource.
type ContainerConfigurationArgs struct {
	CompartmentId pulumi.StringInput
	// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
	IsRepositoryCreatedOnFirstPush pulumi.BoolInput
}

func (ContainerConfigurationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*containerConfigurationArgs)(nil)).Elem()
}

type ContainerConfigurationInput interface {
	pulumi.Input

	ToContainerConfigurationOutput() ContainerConfigurationOutput
	ToContainerConfigurationOutputWithContext(ctx context.Context) ContainerConfigurationOutput
}

func (*ContainerConfiguration) ElementType() reflect.Type {
	return reflect.TypeOf((**ContainerConfiguration)(nil)).Elem()
}

func (i *ContainerConfiguration) ToContainerConfigurationOutput() ContainerConfigurationOutput {
	return i.ToContainerConfigurationOutputWithContext(context.Background())
}

func (i *ContainerConfiguration) ToContainerConfigurationOutputWithContext(ctx context.Context) ContainerConfigurationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerConfigurationOutput)
}

// ContainerConfigurationArrayInput is an input type that accepts ContainerConfigurationArray and ContainerConfigurationArrayOutput values.
// You can construct a concrete instance of `ContainerConfigurationArrayInput` via:
//
//	ContainerConfigurationArray{ ContainerConfigurationArgs{...} }
type ContainerConfigurationArrayInput interface {
	pulumi.Input

	ToContainerConfigurationArrayOutput() ContainerConfigurationArrayOutput
	ToContainerConfigurationArrayOutputWithContext(context.Context) ContainerConfigurationArrayOutput
}

type ContainerConfigurationArray []ContainerConfigurationInput

func (ContainerConfigurationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ContainerConfiguration)(nil)).Elem()
}

func (i ContainerConfigurationArray) ToContainerConfigurationArrayOutput() ContainerConfigurationArrayOutput {
	return i.ToContainerConfigurationArrayOutputWithContext(context.Background())
}

func (i ContainerConfigurationArray) ToContainerConfigurationArrayOutputWithContext(ctx context.Context) ContainerConfigurationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerConfigurationArrayOutput)
}

// ContainerConfigurationMapInput is an input type that accepts ContainerConfigurationMap and ContainerConfigurationMapOutput values.
// You can construct a concrete instance of `ContainerConfigurationMapInput` via:
//
//	ContainerConfigurationMap{ "key": ContainerConfigurationArgs{...} }
type ContainerConfigurationMapInput interface {
	pulumi.Input

	ToContainerConfigurationMapOutput() ContainerConfigurationMapOutput
	ToContainerConfigurationMapOutputWithContext(context.Context) ContainerConfigurationMapOutput
}

type ContainerConfigurationMap map[string]ContainerConfigurationInput

func (ContainerConfigurationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ContainerConfiguration)(nil)).Elem()
}

func (i ContainerConfigurationMap) ToContainerConfigurationMapOutput() ContainerConfigurationMapOutput {
	return i.ToContainerConfigurationMapOutputWithContext(context.Background())
}

func (i ContainerConfigurationMap) ToContainerConfigurationMapOutputWithContext(ctx context.Context) ContainerConfigurationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ContainerConfigurationMapOutput)
}

type ContainerConfigurationOutput struct{ *pulumi.OutputState }

func (ContainerConfigurationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ContainerConfiguration)(nil)).Elem()
}

func (o ContainerConfigurationOutput) ToContainerConfigurationOutput() ContainerConfigurationOutput {
	return o
}

func (o ContainerConfigurationOutput) ToContainerConfigurationOutputWithContext(ctx context.Context) ContainerConfigurationOutput {
	return o
}

func (o ContainerConfigurationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ContainerConfiguration) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Whether to create a new container repository when a container is pushed to a new repository path. Repositories created in this way belong to the root compartment.
func (o ContainerConfigurationOutput) IsRepositoryCreatedOnFirstPush() pulumi.BoolOutput {
	return o.ApplyT(func(v *ContainerConfiguration) pulumi.BoolOutput { return v.IsRepositoryCreatedOnFirstPush }).(pulumi.BoolOutput)
}

// The tenancy namespace used in the container repository path.
func (o ContainerConfigurationOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *ContainerConfiguration) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

type ContainerConfigurationArrayOutput struct{ *pulumi.OutputState }

func (ContainerConfigurationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ContainerConfiguration)(nil)).Elem()
}

func (o ContainerConfigurationArrayOutput) ToContainerConfigurationArrayOutput() ContainerConfigurationArrayOutput {
	return o
}

func (o ContainerConfigurationArrayOutput) ToContainerConfigurationArrayOutputWithContext(ctx context.Context) ContainerConfigurationArrayOutput {
	return o
}

func (o ContainerConfigurationArrayOutput) Index(i pulumi.IntInput) ContainerConfigurationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ContainerConfiguration {
		return vs[0].([]*ContainerConfiguration)[vs[1].(int)]
	}).(ContainerConfigurationOutput)
}

type ContainerConfigurationMapOutput struct{ *pulumi.OutputState }

func (ContainerConfigurationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ContainerConfiguration)(nil)).Elem()
}

func (o ContainerConfigurationMapOutput) ToContainerConfigurationMapOutput() ContainerConfigurationMapOutput {
	return o
}

func (o ContainerConfigurationMapOutput) ToContainerConfigurationMapOutputWithContext(ctx context.Context) ContainerConfigurationMapOutput {
	return o
}

func (o ContainerConfigurationMapOutput) MapIndex(k pulumi.StringInput) ContainerConfigurationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ContainerConfiguration {
		return vs[0].(map[string]*ContainerConfiguration)[vs[1].(string)]
	}).(ContainerConfigurationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ContainerConfigurationInput)(nil)).Elem(), &ContainerConfiguration{})
	pulumi.RegisterInputType(reflect.TypeOf((*ContainerConfigurationArrayInput)(nil)).Elem(), ContainerConfigurationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ContainerConfigurationMapInput)(nil)).Elem(), ContainerConfigurationMap{})
	pulumi.RegisterOutputType(ContainerConfigurationOutput{})
	pulumi.RegisterOutputType(ContainerConfigurationArrayOutput{})
	pulumi.RegisterOutputType(ContainerConfigurationMapOutput{})
}